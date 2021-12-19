from json import loads as json_loads
from dataclasses import dataclass
from enum import Enum

import frida

ALL_METHODS_HOOK = '*'

@dataclass(frozen=False)
class HTTPFlow:
    """
    Represent an HTTP flow from the Xiaomi Wear app. Each flow is identified by its unique nonce, used to encrypt the
    request data on the device and the response data on the server. This is used by the HookManager in order to match
    the request to the response.
    """
    nonce: str
    method: str
    route: str
    req_body: str
    res_body: str

class HookDataType(Enum):
    """
    Enumerates the possible data types that can be sent from the server to the manager.
    """
    REQUEST = 'request'
    RESPONSE = 'response'

class HookManager:
    def __init__(self):
        self._hooks = {}
        self._flows = {}

        self.verbose = False

    def add_hook(self, route: str, method: str, hook_func):
        if route not in self._hooks:
            self._hooks[route] = {}

        self._hooks[route][method] = hook_func

    def _handle_request_message(self, nonce: str, data: dict):
        self._flows[nonce] = HTTPFlow(
            nonce=nonce,
            method=data['method'],
            route=data['route'],
            req_body=data['body'],
            res_body=''
        )

    def _handle_response_message(self, nonce: str, data: dict):
        if nonce not in self._flows:
            print(f"{nonce} doesn't exist!")
            return

        flow = self._flows[nonce]
        flow.res_body = data['body']
        route = flow.route
        method = flow.method

        if self.verbose:
            print(flow)

        if route in self._hooks:
            method_pattern = method if method in self._hooks[route] else ALL_METHODS_HOOK
            if method_pattern in self._hooks[route]:
                hook = self._hooks[route][method_pattern]
                return hook(flow)

    def handle_message(self, message, *args, **kwargs):
        data = json_loads(message['payload'])
        data_type = HookDataType(data['type'])
        nonce = data['nonce']

        if data_type is HookDataType.REQUEST:
            return self._handle_request_message(nonce, data)

        if data_type is HookDataType.RESPONSE:
            return self._handle_response_message(nonce, data)

def hook(manager: HookManager, route: str, method=ALL_METHODS_HOOK):
    def hook_decorator(func):
        manager.add_hook(route, method, func)
    return hook_decorator
