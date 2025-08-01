import threading
import time
import re
import logging
import sys
import os
import pytest
from multiprocessing.pool import ThreadPool
from collections import deque

from .helpers.assertions import pytest_assert
from .platform.interface_utils import check_interface_status_of_up_ports
from .platform.processes_utils import wait_critical_processes
from .plugins.loganalyzer.utils import support_ignore_loganalyzer
from .utilities import wait_until, get_plt_reboot_ctrl
from tests.common.helpers.dut_utils import ignore_t2_syslog_msgs, create_duthost_console, creds_on_dut
from tests.common.fixtures.conn_graph_facts import get_graph_facts

logger = logging.getLogger(__name__)

# Create the waiting power on event
power_on_event = threading.Event()

# SSH defines
SONIC_SSH_PORT = 22
SONIC_SSH_REGEX = 'OpenSSH_[\\w\\.]+ Debian'

REBOOT_TYPE_WARM = "warm"
REBOOT_TYPE_SAI_WARM = "sai-warm"
REBOOT_TYPE_COLD = "cold"
REBOOT_TYPE_SOFT = "soft"
REBOOT_TYPE_FAST = "fast"
REBOOT_TYPE_POWEROFF = "power off"
REBOOT_TYPE_WATCHDOG = "watchdog"
REBOOT_TYPE_UNKNOWN = "Unknown"
REBOOT_TYPE_THERMAL_OVERLOAD = "Thermal Overload"
REBOOT_TYPE_BIOS = "bios"
REBOOT_TYPE_ASIC = "asic"
REBOOT_TYPE_KERNEL_PANIC = "Kernel Panic"
REBOOT_TYPE_SUPERVISOR = "Reboot from Supervisor"
REBOOT_TYPE_SUPERVISOR_HEARTBEAT_LOSS = "Heartbeat with the Supervisor card lost"

# Event to signal DUT activeness
DUT_ACTIVE = threading.Event()
DUT_ACTIVE.set()

'''
    command                : command to reboot the DUT
    timeout                : timeout waiting for DUT to come back after reboot
    wait                   : time wait for switch the stablize
    cause                  : search string to determine reboot cause
    test_reboot_cause_only : indicate if the purpose of test is for reboot cause only
'''
reboot_ctrl_dict = {
    REBOOT_TYPE_SOFT: {
        "command": "soft-reboot",
        "timeout": 300,
        "wait": 120,
        "cause": "soft-reboot",
        "test_reboot_cause_only": False
    },
    REBOOT_TYPE_FAST: {
        "command": "fast-reboot",
        "timeout": 180,
        "wait": 120,
        "warmboot_finalizer_timeout": 180,
        "cause": "fast-reboot",
        "test_reboot_cause_only": False
    },
    REBOOT_TYPE_WARM: {
        "command": "warm-reboot",
        "timeout": 300,
        "wait": 90,
        "warmboot_finalizer_timeout": 180,
        "cause": "warm-reboot",
        "test_reboot_cause_only": False
    },
    REBOOT_TYPE_WATCHDOG: {
        "command": "watchdogutil arm -s 5",
        "timeout": 300,
        "wait": 120,
        "cause": "Watchdog",
        "test_reboot_cause_only": True
    },
    REBOOT_TYPE_SAI_WARM: {
        "command": "/usr/bin/sai_warmboot.sh",
        "timeout": 300,
        "wait": 90,
        "warmboot_finalizer_timeout": 30,
        "cause": "warm-reboot",
        "test_reboot_cause_only": False
    },
    REBOOT_TYPE_BIOS: {
        "timeout": 300,
        "wait": 120,
        "cause": "BIOS",
        "test_reboot_cause_only": True
    },
    REBOOT_TYPE_ASIC: {
        "timeout": 300,
        "wait": 120,
        "cause": "ASIC",
        "test_reboot_cause_only": True
    },
    REBOOT_TYPE_KERNEL_PANIC: {
        "command": 'nohup bash -c "sleep 5 && echo c > /proc/sysrq-trigger" &',
        "timeout": 300,
        "wait": 120,
        "cause": "Kernel Panic",
        "test_reboot_cause_only": True
    },
    REBOOT_TYPE_SUPERVISOR: {
        "command": "reboot",
        "timeout": 300,
        "wait": 120,
        # When linecards are rebooted due to supervisor cold reboot
        "cause": r"Reboot from Supervisor|reboot from Supervisor",
        "test_reboot_cause_only": False
    },
    REBOOT_TYPE_SUPERVISOR_HEARTBEAT_LOSS: {
        "command": "reboot",
        "timeout": 300,
        "wait": 120,
        # When linecards are rebooted due to supervisor crash/abnormal reboot
        "cause": r"Heartbeat|headless",
        "test_reboot_cause_only": False
    },
    REBOOT_TYPE_COLD: {
        "command": "reboot",
        "timeout": 300,
        "wait": 120,
        # We are searching two types of reboot cause.
        # This change relates to changes of PR #6130 in sonic-buildimage repository
        "cause": r"'reboot'|Non-Hardware \(reboot|^reboot",
        "test_reboot_cause_only": False
    },
    REBOOT_TYPE_POWEROFF: {
        "timeout": 300,
        "wait": 120,
        "cause": "Power Loss",
        "test_reboot_cause_only": True
    }
}

'''
command : command to reboot the smartswitch DUT
'''
reboot_ss_ctrl_dict = {
    REBOOT_TYPE_COLD: {
        "command": "reboot",
        "timeout": 300,
        "wait": 120,
        "cause": r"'reboot'|Non-Hardware \(reboot|^reboot",
        "test_reboot_cause_only": False
        },
    REBOOT_TYPE_WATCHDOG: {
        "command": "watchdogutil arm -s 5",
        "timeout": 300,
        "wait": 120,
        "cause": "Watchdog",
        "test_reboot_cause_only": True
    }
}

MAX_NUM_REBOOT_CAUSE_HISTORY = 10
REBOOT_TYPE_HISTOYR_QUEUE = deque([], MAX_NUM_REBOOT_CAUSE_HISTORY)
REBOOT_CAUSE_HISTORY_TITLE = ["name", "cause", "time", "user", "comment"]

# Retry logic config
MAX_RETRIES = 3
RETRY_BACKOFF_TIME = 15


def check_warmboot_finalizer_inactive(duthost):
    """
    Check if warmboot finalizer service is exited
    """
    stdout = duthost.command('systemctl is-active warmboot-finalizer.service', module_ignore_errors=True)['stdout']
    return 'inactive' == stdout.strip()


def wait_for_shutdown(duthost, localhost, delay, timeout, reboot_res):
    hostname = duthost.hostname
    dut_ip = duthost.mgmt_ip
    logger.info('waiting for ssh to drop on {}'.format(hostname))
    res = localhost.wait_for(host=dut_ip,
                             port=SONIC_SSH_PORT,
                             state='absent',
                             search_regex=SONIC_SSH_REGEX,
                             delay=delay,
                             timeout=timeout,
                             module_ignore_errors=True)

    if res.is_failed or ('msg' in res and 'Timeout' in res['msg']):
        if reboot_res.ready():
            logger.error('reboot result: {} on {}'.format(reboot_res.get(), hostname))
        raise Exception('DUT {} did not shutdown'.format(hostname))


def wait_for_startup(duthost, localhost, delay, timeout, port=SONIC_SSH_PORT):
    # TODO: add serial output during reboot for better debuggability
    #       This feature requires serial information to be present in
    #       testbed information
    hostname = duthost.hostname
    dut_ip = duthost.mgmt_ip
    logger.info('waiting for ssh to startup on {}'.format(hostname))
    is_ssh_connected, res, num_tries = ssh_connection_with_retry(
        localhost=localhost,
        host_ip=dut_ip,
        port=port,
        delay=delay,
        timeout=timeout,
    )
    if num_tries > 1:
        collect_mgmt_config_by_console(duthost, localhost)
        if not is_ssh_connected:
            raise Exception(f'DUT {hostname} did not startup. res: {res}')
        else:
            raise Exception(f'DUT {hostname} did not startup at first try. res: {res}')

    logger.info('ssh has started up on {}'.format(hostname))


def perform_reboot(duthost, pool, reboot_command, reboot_helper=None, reboot_kwargs=None, reboot_type='cold'):
    # pool for executing tasks asynchronously
    hostname = duthost.hostname

    def execute_reboot_command():
        logger.info('rebooting {} with command "{}"'.format(hostname, reboot_command))
        return duthost.command(reboot_command)

    def execute_reboot_helper():
        logger.info('rebooting {} with helper "{}"'.format(hostname, reboot_helper))
        return reboot_helper(reboot_kwargs, power_on_event)

    dut_datetime = duthost.get_now_time(utc_timezone=True)
    DUT_ACTIVE.clear()

    # Extend ignore fabric port msgs for T2 chassis with DNX chipset on Linecards
    ignore_t2_syslog_msgs(duthost)

    if reboot_type != REBOOT_TYPE_POWEROFF:
        reboot_res = pool.apply_async(execute_reboot_command)
    else:
        assert reboot_helper is not None, "A reboot function must be provided for power off/on reboot"
        reboot_res = pool.apply_async(execute_reboot_helper)
    return [reboot_res, dut_datetime]


@support_ignore_loganalyzer
def reboot_smartswitch(duthost, reboot_type=REBOOT_TYPE_COLD):
    """
    reboots SmartSwitch or a DPU
    :param duthost: DUT host object
    :param reboot_type: reboot type (cold)
    """

    if reboot_type not in reboot_ss_ctrl_dict:
        pytest.skip(
            "Skipping the reboot test as the reboot type {} is not supported on smartswitch".format(reboot_type))
        return

    hostname = duthost.hostname
    dut_datetime = duthost.get_now_time(utc_timezone=True)

    logging.info("Rebooting the DUT {} with type {}".format(hostname, reboot_type))

    reboot_res = duthost.command(reboot_ss_ctrl_dict[reboot_type]["command"])

    return [reboot_res, dut_datetime]


def check_dshell_ready(duthost):
    show_command = "sudo show platform npu rx cgm_global"
    err_msg = "debug shell server for asic 0 is not running"
    output = duthost.command(show_command)['stdout']
    if err_msg in output:
        return False
    return True


@support_ignore_loganalyzer
def reboot(duthost, localhost, reboot_type='cold', delay=10,
           timeout=0, wait=0, wait_for_ssh=True, wait_warmboot_finalizer=False, warmboot_finalizer_timeout=0,
           reboot_helper=None, reboot_kwargs=None, return_after_reconnect=False,
           safe_reboot=False, check_intf_up_ports=False, wait_for_bgp=False,  wait_for_ibgp=True):
    """
    reboots DUT
    :param duthost: DUT host object
    :param localhost:  local host object
    :param reboot_type: reboot type (cold, fast, warm)
    :param delay: delay between ssh availability checks
    :param timeout: timeout for waiting ssh port state change
    :param wait: time to wait for DUT to initialize
    :param wait_for_ssh: Wait for SSH startup
    :param return_after_reconnect: Return from function as soon as SSH reconnects
    :param wait_warmboot_finalizer: Wait for WARMBOOT_FINALIZER done
    :param warmboot_finalizer_timeout: Timeout for waiting WARMBOOT_FINALIZER
    :param reboot_helper: helper function to execute the power toggling
    :param reboot_kwargs: arguments to pass to the reboot_helper
    :param safe_reboot: arguments to wait DUT ready after reboot
    :param check_intf_up_ports: arguments to check interface after reboot
    :param wait_for_bgp: arguments to wait for BGP after reboot
    :param wait_for_ibgp: True to wait for all iBGP connections to come up after device reboot. This
                          parameter is only used when `wait_for_bgp` is True
    :return:
    """
    assert not (safe_reboot and return_after_reconnect)
    pool = ThreadPool()
    hostname = duthost.hostname
    try:
        tc_name = os.environ.get('PYTEST_CURRENT_TEST').split(' ')[0]
        plt_reboot_ctrl = get_plt_reboot_ctrl(duthost, tc_name, reboot_type)
        reboot_ctrl = reboot_ctrl_dict[reboot_type]
        reboot_command = reboot_ctrl['command'] if reboot_type != REBOOT_TYPE_POWEROFF else None
        if timeout == 0:
            timeout = reboot_ctrl['timeout']
        if wait == 0:
            wait = reboot_ctrl['wait']
        if plt_reboot_ctrl:
            # use 'wait' and 'timeout' overrides from inventory if they are specified
            wait = plt_reboot_ctrl.get('wait', wait)
            timeout = plt_reboot_ctrl.get('timeout', timeout)
        if warmboot_finalizer_timeout == 0 and 'warmboot_finalizer_timeout' in reboot_ctrl:
            warmboot_finalizer_timeout = reboot_ctrl['warmboot_finalizer_timeout']
        if duthost.get_facts().get("modular_chassis") and safe_reboot:
            wait = max(wait, 600)
            timeout = max(timeout, 420)
    except KeyError:
        raise ValueError('invalid reboot type: "{} for {}"'.format(reboot_type, hostname))
    logger.info('Reboot {}: wait[{}], timeout[{}]'.format(hostname, wait, timeout))
    # Create a temporary file in tmpfs before reboot
    logger.info('DUT {} create a file /dev/shm/test_reboot before rebooting'.format(hostname))
    duthost.command('sudo touch /dev/shm/test_reboot')
    # Get reboot-cause history before reboot
    logger.info('DUT OS Version: {}'.format(duthost.os_version))
    prev_reboot_cause_history = None
    # prev_reboot_cause_history is only used for T2 device.
    if duthost.get_facts().get("modular_chassis") and reboot_type == REBOOT_TYPE_POWEROFF:
        logger.info('Fetching reboot cause history before rebooting')
        prev_reboot_cause_history = duthost.show_and_parse("show reboot-cause history")

    wait_conlsole_connection = 5
    console_thread_res = pool.apply_async(
        collect_console_log, args=(duthost, localhost, timeout + wait_conlsole_connection))
    time.sleep(wait_conlsole_connection)
    # Perform reboot
    if duthost.dut_basic_facts()['ansible_facts']['dut_basic_facts'].get("is_smartswitch"):
        reboot_res, dut_datetime = reboot_smartswitch(duthost, reboot_type)
    else:
        reboot_res, dut_datetime = perform_reboot(duthost, pool, reboot_command, reboot_helper,
                                                  reboot_kwargs, reboot_type)

    wait_for_shutdown(duthost, localhost, delay, timeout, reboot_res)

    # Release event to proceed poweron for PDU.
    power_on_event.set()

    # if wait_for_ssh flag is False, do not wait for dut to boot up
    if not wait_for_ssh:
        return
    try:
        wait_for_startup(duthost, localhost, delay, timeout)
    except Exception as err:
        logger.error('collecting console log thread result: {} on {}'.format(console_thread_res.get(), hostname))
        pool.terminate()
        raise Exception(f"dut not start: {err}")

    if return_after_reconnect:
        return

    logger.info('waiting for switch {} to initialize'.format(hostname))
    if safe_reboot:
        # The wait time passed in might not be guaranteed to cover the actual
        # time it takes for containers to come back up. Therefore, add 5
        # minutes to the maximum wait time. If it's ready sooner, then the
        # function will return sooner.

        # Update critical service list after rebooting in case critical services changed after rebooting
        pytest_assert(wait_until(200, 10, 0, duthost.is_critical_processes_running_per_asic_or_host, "database"),
                      "Database not start.")
        pytest_assert(wait_until(20, 5, 0, duthost.is_service_running, "redis", "database"), "Redis DB not start")

        duthost.critical_services_tracking_list()
        pytest_assert(wait_until(wait + 400, 20, 0, duthost.critical_services_fully_started),
                      "{}: All critical services should be fully started!".format(hostname))
        wait_critical_processes(duthost)

        if check_intf_up_ports:
            pytest_assert(wait_until(wait + 300, 20, 0, check_interface_status_of_up_ports, duthost),
                          "{}: Not all ports that are admin up on are operationally up".format(hostname))

        if duthost.facts['asic_type'] == "cisco-8000":
            # Wait dshell initialization finish
            pytest_assert(wait_until(wait + 300, 20, 0, check_dshell_ready, duthost),
                          "dshell not ready")
    else:
        time.sleep(wait)

    # Wait warmboot-finalizer service
    if (reboot_type == REBOOT_TYPE_WARM or reboot_type == REBOOT_TYPE_FAST) and wait_warmboot_finalizer:
        logger.info('waiting for warmboot-finalizer service to finish on {}'.format(hostname))
        ret = wait_until(warmboot_finalizer_timeout, 5, 0, check_warmboot_finalizer_inactive, duthost)
        if not ret:
            raise Exception('warmboot-finalizer service timeout on DUT {}'.format(hostname))

    # Verify if the temporary file created in tmpfs is deleted after reboot, to determine a
    # successful reboot
    file_check = duthost.stat(path="/dev/shm/test_reboot")
    if file_check['stat']['exists']:
        raise Exception('DUT {} did not reboot'.format(hostname))

    DUT_ACTIVE.set()
    logger.info('{} reboot finished on {}'.format(reboot_type, hostname))
    pool.terminate()
    dut_uptime = duthost.get_up_time(utc_timezone=True)
    logger.info('DUT {} up since {}'.format(hostname, dut_uptime))
    # some device does not have onchip clock and requires obtaining system time a little later from ntp
    # or SUP to obtain the correct time so if the uptime is less than original device time, it means it
    # is most likely due to this issue which we can wait a little more until the correct time is set in place.

    # Use an alternative reboot check if T2 device and REBOOT_TYPE_POWEROFF
    if duthost.get_facts().get("modular_chassis") and reboot_type == REBOOT_TYPE_POWEROFF:
        wait_until(120, 5, 0, duthost.critical_processes_running, "database")
        time.sleep(60)
        curr_reboot_cause_history = duthost.show_and_parse("show reboot-cause history")
        pytest_assert(prev_reboot_cause_history != curr_reboot_cause_history, "No new input into history-queue")
    else:
        if float(dut_uptime.strftime("%s")) < float(dut_datetime.strftime("%s")):
            logger.info('DUT {} timestamp went backwards'.format(hostname))
            wait_until(120, 5, 0, positive_uptime, duthost, dut_datetime)

        dut_uptime = duthost.get_up_time()

        assert float(dut_uptime.strftime("%s")) > float(dut_datetime.strftime("%s")), "Device {} did not reboot". \
            format(hostname)

    if wait_for_bgp:
        bgp_neighbors = duthost.get_bgp_neighbors_per_asic(state="all")
        if not wait_for_ibgp:
            # Filter out iBGP neighbors
            filtered_bgp_neighbors = {}
            for asic, interfaces in bgp_neighbors.items():
                filtered_interfaces = {
                    ip: details for ip, details in interfaces.items()
                    if details["local AS"] != details["remote AS"]
                }

                if filtered_interfaces:
                    filtered_bgp_neighbors[asic] = filtered_interfaces

            bgp_neighbors = filtered_bgp_neighbors

        pytest_assert(
            wait_until(wait + 300, 10, 0, duthost.check_bgp_session_state_all_asics, bgp_neighbors),
            "Not all bgp sessions are established after reboot",
        )


def positive_uptime(duthost, dut_datetime):
    dut_uptime = duthost.get_up_time()
    if float(dut_uptime.strftime("%s")) < float(dut_datetime.strftime("%s")):
        return False

    return True


def get_reboot_cause(dut):
    """
    @summary: get the reboot cause on DUT.
    @param dut: The AnsibleHost object of DUT.
    """
    logger.info('Getting reboot cause from dut {}'.format(dut.hostname))
    output = dut.shell('show reboot-cause')
    cause = output['stdout']

    # For kvm testbed, the expected output of command `show reboot-cause`
    # is such like "User issued 'xxx' command [User: admin, Time: Sun Aug  4 06:43:19 PM UTC 2024]"
    # So, use the above pattern to get real reboot cause
    if dut.facts["asic_type"] == "vs":
        match = re.search("User issued '(.*)' command", cause)
        if match:
            cause = match.groups()[0]

    for type, ctrl in list(reboot_ctrl_dict.items()):
        if dut.facts['asic_type'] == "cisco-8000" and dut.get_facts().get("modular_chassis") \
           and type == REBOOT_TYPE_SUPERVISOR_HEARTBEAT_LOSS:
            # Skip the check for SUP heartbeat loss on T2 chassis
            if re.search(r"Heartbeat|headless|Power Loss", cause):
                return type
        else:
            if re.search(ctrl['cause'], cause):
                return type

    return REBOOT_TYPE_UNKNOWN


def check_reboot_cause(dut, reboot_cause_expected):
    """
    @summary: Check the reboot cause on DUT. Can be used with wailt_until
    @param dut: The AnsibleHost object of DUT.
    @param reboot_cause_expected: The expected reboot cause.
    """
    reboot_cause_got = get_reboot_cause(dut)
    logger.debug("dut {} last reboot-cause {}".format(dut.hostname, reboot_cause_got))
    return reboot_cause_got == reboot_cause_expected


def sync_reboot_history_queue_with_dut(dut):
    """
    @summary: Sync DUT and internal history queues
    @param dut: The AnsibleHost object of DUT.
    """

    global REBOOT_TYPE_HISTOYR_QUEUE
    global MAX_NUM_REBOOT_CAUSE_HISTORY

    # Initialize local deque for storing DUT reboot cause history
    dut_reboot_history_queue = deque([], MAX_NUM_REBOOT_CAUSE_HISTORY)

    # Skip this function if sonic image is 201811 or 201911
    if "201811" in dut.os_version or "201911" in dut.os_version:
        logger.info("Skip sync reboot-cause history for version before 202012")
        return

    # IF control is here it means the SONiC image version is > 201911
    # Try and get the entire reboot-cause history from DUT

    # Retry logic for increased robustness
    dut_reboot_history_received = False
    for retry_count in range(MAX_RETRIES):
        try:
            # Try and get the current reboot history from DUT
            # If received, set flag and break out of for loop

            dut_reboot_history_queue = dut.show_and_parse("show reboot-cause history")
            dut_reboot_history_received = True
            break
        except Exception:
            e_type, e_value, e_traceback = sys.exc_info()
            logger.info("Exception type: %s" % e_type.__name__)
            logger.info("Exception message: %s" % e_value)
            logger.info("Backing off for %d seconds before retrying", ((retry_count + 1) * RETRY_BACKOFF_TIME))

            time.sleep(((retry_count + 1) * RETRY_BACKOFF_TIME))
            continue

    # If retry logic did not yield reboot cause history from DUT,
    # return without clearing the existing reboot history queue.
    if not dut_reboot_history_received:
        logger.warning("Unable to sync reboot history queue")
        return

    # If the reboot cause history is received from DUT,
    # we sync the two queues. TO that end,
    # Clear the current reboot history queue
    REBOOT_TYPE_HISTOYR_QUEUE.clear()

    # For each item in the DUT reboot queue,
    # iterate through every item in the reboot dict until
    # a "cause" match is found. Then add that key to the
    # reboot history queue REBOOT_TYPE_HISTOYR_QUEUE
    # If no cause is found add 'Unknown' as reboot type.

    # NB: appendleft used because queue received from DUT
    #     is in reverse-chronological order.

    for reboot_type in (dut_reboot_history_queue):
        dict_iter_found = False
        for dict_iter in (reboot_ctrl_dict):
            if re.search(reboot_ctrl_dict[dict_iter]["cause"], reboot_type["cause"]):
                logger.info("Adding {} to REBOOT_TYPE_HISTOYR_QUEUE".format(dict_iter))
                REBOOT_TYPE_HISTOYR_QUEUE.appendleft(dict_iter)
                dict_iter_found = True
                break
        if not dict_iter_found:
            logger.info("Adding {} to REBOOT_TYPE_HISTOYR_QUEUE".format(REBOOT_TYPE_UNKNOWN))
            REBOOT_TYPE_HISTOYR_QUEUE.appendleft(REBOOT_TYPE_UNKNOWN)


def check_reboot_cause_history(dut, reboot_type_history_queue):
    """
    @summary: Check the reboot cause history on DUT. Can be used with wailt_until
    @param dut: The AnsibleHost object of DUT.
    @param reboot_type_history_queue: reboot type queue.
    e.g.
    show reboot-cause  history
    Name                 Cause          Time                             User    Comment
    -------------------  -------------  -------------------------------  ------  ---------
    2021_09_09_14_15_13  Power Loss ()  N/A                              N/A     N/A
    2021_09_09_14_06_17  reboot         Thu 09 Sep 2021 02:05:17 PM UTC  admin   N/A
    2021_09_09_13_59_11  Watchdog ()    N/A                              N/A     N/A
    2021_09_09_13_52_13  Power Loss ()  N/A                              N/A     N/A
    2021_09_09_13_45_18  warm-reboot    Thu 09 Sep 2021 01:44:14 PM UTC  admin   N/A
    2021_09_09_13_37_58  fast-reboot    Thu 09 Sep 2021 01:37:09 PM UTC  admin   N/A
    2021_09_09_13_30_52  soft-reboot    Thu 09 Sep 2021 01:30:24 PM UTC  admin   N/A
    2021_09_09_13_24_17  reboot         Thu 09 Sep 2021 01:23:17 PM UTC  admin   N/A
    """
    reboot_cause_history_got = dut.show_and_parse("show reboot-cause history")
    logger.debug("dut {} reboot-cause history {}. reboot type history queue is {}".format(
        dut.hostname, reboot_cause_history_got, reboot_type_history_queue))

    # For kvm testbed, command `show reboot-cause history` will return None
    # So, return in advance if this check is running on kvm.
    if dut.facts["asic_type"] == "vs":
        return True

    logger.info("Verify reboot-cause history title")
    if reboot_cause_history_got:
        if not set(REBOOT_CAUSE_HISTORY_TITLE) == set(reboot_cause_history_got[0].keys()):
            logger.error("Expected reboot-cause history title:{} not match actual reboot-cause history title:{}".
                         format(REBOOT_CAUSE_HISTORY_TITLE, list(reboot_cause_history_got[0].keys())))
            return False

    logger.info("Verify reboot-cause output are sorted in reverse chronological order")
    reboot_type_history_len = len(reboot_type_history_queue)
    if reboot_type_history_len <= len(reboot_cause_history_got):
        for index, reboot_type in enumerate(reboot_type_history_queue):
            if reboot_type not in reboot_ctrl_dict:
                logger.warning(
                    "Reboot type: {} not in dictionary. Skipping history check for this entry.".format(reboot_type)
                )

                continue
            logger.info("index:  %d, reboot cause: %s, reboot cause from DUT: %s" %
                        (index, reboot_ctrl_dict[reboot_type]["cause"],
                         reboot_cause_history_got[reboot_type_history_len - index - 1]["cause"]))
            if not re.search(reboot_ctrl_dict[reboot_type]["cause"],
                             reboot_cause_history_got[reboot_type_history_len - index - 1]["cause"]):
                logger.error("The {} reboot-cause not match. expected_reboot type={}, actual_reboot_cause={}".format(
                    index, reboot_ctrl_dict[reboot_type]["cause"],
                    reboot_cause_history_got[reboot_type_history_len - index]["cause"]))
                return False
        return True
    logger.error("The number of expected reboot-cause:{} is more than that of actual reboot-cuase:{}".format(
        reboot_type_history_len, len(reboot_type_history_queue)))
    return False


def check_determine_reboot_cause_service(dut):
    """
    @summary: This function verifies the status of the 'determine-reboot-cause' service on the device under test (DUT).
    It checks the service's ActiveState and SubState using systemctl.
    @param dut: The AnsibleHost object of DUT.
    """
    # Check the 'determine-reboot-cause' service status
    logger.info("Checking 'determine-reboot-cause' service status using systemctl")
    service_state = dut.get_service_props("determine-reboot-cause.service")

    # Validate service is active
    active_state = service_state.get("ActiveState", "")
    sub_state = service_state.get("SubState", "")
    logger.info(f"'determine-reboot-cause' ActiveState: {active_state}, SubState: {sub_state}")

    assert active_state == "active", f"Service 'determine-reboot-cause' is not active. Current state: {active_state}"
    assert sub_state == "exited", f"Service 'determine-reboot-cause' did not exit cleanly. \
            Current sub-state: {sub_state}"


def try_create_dut_console(duthost, localhost, conn_graph_facts, creds):
    try:
        dut_sonsole = create_duthost_console(duthost, localhost, conn_graph_facts, creds)
    except Exception as err:
        logger.warning(f"Fail to create dut console. Please check console config or if console works ro not. {err}")
        return None
    logger.info("creating dut console succeeds")
    return dut_sonsole


def collect_console_log(duthost, localhost, timeout):
    logger.info("start: collect console log")
    creds = creds_on_dut(duthost)
    conn_graph_facts = get_graph_facts(duthost, localhost, [duthost.hostname])
    dut_console = try_create_dut_console(duthost, localhost, conn_graph_facts, creds)
    if dut_console:
        logger.info(f"sleep {timeout} to collect console log....")
        time.sleep(timeout)
        dut_console.disconnect()
        logger.info('end: collect console log')
    else:
        logger.warning("dut console is not ready, we cannot get log by console")


def check_ssh_connection(localhost, host_ip, port, delay, timeout, search_regex):
    res = localhost.wait_for(host=host_ip,
                             port=port,
                             state='started',
                             search_regex=search_regex,
                             delay=delay,
                             timeout=timeout,
                             module_ignore_errors=True)
    is_connected = not (res.is_failed or ('msg' in res and 'Timeout' in res['msg']))
    return is_connected, res


def ssh_connection_with_retry(localhost, host_ip, port, delay, timeout):
    '''
    Connects to the DUT via SSH. If the connection attempt fails,
    a retry is performed with a reduced timeout and without expecting any specific message (`search_regex=None`).
    :param localhost:  local host object
    :param host_ip: dut ip
    :param delay: delay between ssh availability checks
    :param delay: sonic ssh port
    :param timeout: timeout for waiting ssh port state change
    :return: A tuple containing two elements:
    - A boolean indicating the result of the SSH connection attempt.
    - The result of the SSH connection last attempt.
    '''
    default_connection_params = {
        'host_ip': host_ip,
        'port': port,
        'delay': delay,
        'timeout': timeout,
        'search_regex': SONIC_SSH_REGEX
    }
    short_timeout = 40
    params_to_update_list = [{}, {'search_regex': None, 'timeout': short_timeout}]
    for num_try, params_to_update in enumerate(params_to_update_list):
        iter_connection_params = default_connection_params.copy()
        iter_connection_params.update(params_to_update)
        logger.info(f"Checking ssh connection using the following params: {iter_connection_params}")
        is_ssh_connected, ssh_retry_res = check_ssh_connection(
            localhost=localhost,
            **iter_connection_params
        )
        if is_ssh_connected:
            logger.info("Connection succeeded")
            break
        logger.info("Connection failed")
        logger.info("Check if dut pingable")
        ping_result = localhost.shell(f"ping -c 3 {host_ip}", module_ignore_errors=True)
        if ping_result['rc'] == 0:
            logger.info("Ping to dut was successful")
        else:
            logger.info("Ping to dut failed")
    num_tries = num_try + 1
    return is_ssh_connected, ssh_retry_res, num_tries


def collect_mgmt_config_by_console(duthost, localhost):
    logger.info("check if dut is pingable")
    localhost.shell(f"ping -c 5 {duthost.mgmt_ip}", module_ignore_errors=True)

    logger.info("Start: collect mgmt config by console")
    creds = creds_on_dut(duthost)
    conn_graph_facts = get_graph_facts(duthost, localhost, [duthost.hostname])
    dut_console = try_create_dut_console(duthost, localhost, conn_graph_facts, creds)
    if dut_console:
        dut_console.send_command("ip a s eth0")
        dut_console.send_command("show ip int")
        dut_console.disconnect()
        logger.info('End: collect mgmt config by  console  ...')
    else:
        logger.warning("dut console is not ready, we can get mgmt config by console")
