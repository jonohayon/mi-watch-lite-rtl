from sys import argv, stdin

from frida import get_device_manager
from frida.core import Device

from .hook_manager import HookManager, hook, HTTPFlow

XIAOMI_WEAR_IDENTIFIER = 'com.xiaomi.wearable'
HOOK_MANAGER = HookManager()

@hook(manager=HOOK_MANAGER, route='/user/get_bound_devices')
def get_bound_devices_hook(flow: HTTPFlow):
    print(flow)

def get_usb_device() -> Device:
    device_manager = get_device_manager()
    return device_manager.get_device_matching(lambda dev: dev.type == 'usb')

def main(server_filename: str):
    device = get_usb_device()
    pid = device.spawn([XIAOMI_WEAR_IDENTIFIER])
    print(f'Launched {XIAOMI_WEAR_IDENTIFIER} at {pid}')
    session = device.attach(pid)
    try:
        with open(server_filename, 'rt') as server_file:
            server_script = server_file.read()
            script = session.create_script(server_script)
            script.on('message', HOOK_MANAGER.handle_message)
            device.resume(pid)
            script.load()

            # Do nothing essentially
            stdin.read()
    except KeyboardInterrupt:
        device.kill(pid)

if __name__ == '__main__':
    main(argv[1])