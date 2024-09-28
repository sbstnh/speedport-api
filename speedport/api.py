import functools
import logging
from datetime import datetime, timedelta

import aiohttp

from speedport import exceptions
from speedport.connection import Connection

_LOGGER = logging.getLogger(__name__)


def need_auth(func):
    @functools.wraps(func)
    async def inner(self: "SpeedportApi", *args, **kwargs):
        if not self.api.is_logged_in:
            if not self.password:
                error = f'You need to set a password to use "{func.__name__}"'
                _LOGGER.error(error)
                raise PermissionError(error)
            await self.api.login(self.password)
        try:
            return await func(self, *args, **kwargs)
        except exceptions.DecryptionKeyError as exception:
            if not self.last_logout:
                _LOGGER.info(f"Paused fetching for {self.pause_time} min")
                self.last_logout = datetime.now()
            if datetime.now() > (
                time := self.last_logout + timedelta(minutes=self.pause_time)
            ):
                self.last_logout = None
                await self.api.login(self.password)
                return await func(self, *args, **kwargs)
            remaining = time - datetime.now()
            error = f"Paused for 00:{remaining.seconds // 60:02d}:{remaining.seconds % 60:02d}"
            _LOGGER.debug(error)
            raise exceptions.LoginPausedError(error) from exception

    return inner


class SpeedportApi:

    _SECURE_STATUS_DATA = "data/SecureStatus.json"
    _IP_PHONE_HANDLER_DATA = "data/IPPhoneHandler.json"
    _ROUTER_DATA = "data/Router.json"
    _STATUS_DATA = "data/Status.json"
    _DEVICES_DATA = "data/DeviceList.json"
    _LOGIN_DATA = "data/Login.json"

    _WPS_REFERRER = "html/content/network/wlan_wps.html"
    _WPS_DATA = "data/WPSStatus.json"

    _WPS_CHANGE_REFERRER = "html/content/network/wlan_wps.html"
    _WPS_CHANGE_DATA = "data/WLANAccess.json"

    _IP_REFERER = "html/content/internet/con_ipdata.html"
    _IP_DATA = "data/IPData.json"

    _PHONE_CALLS_REFERRER = "html/content/phone/phone_call_taken.html"
    _PHONE_CALLS_DATA = "data/PhoneCalls.json"

    _RECONNECT_REFERRER = "html/content/internet/con_ipdata.html"
    _RECONNECT_DATA = "data/Connect.json"

    _REBOOT_REFERRER = "html/content/config/restart.html"
    _REBOOT_DATA = "data/Reboot.json"

    def __init__(
        self,
        host: str = "speedport.ip",
        password: str = "",
        https: bool = False,
        session: aiohttp.ClientSession | None = None,
        pause_time: int = 5,
    ):
        self._api: Connection | None = None
        self._host: str = host
        self._password: str = password
        self._https: bool = https
        self._url = f"https://{host}" if https else f"http://{host}"
        self._session: aiohttp.ClientSession | None = session
        self._pause_time: int = pause_time
        self._last_logout: datetime | None = None

    async def __aenter__(self):
        return await self.create()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def create(self):
        self._api = await Connection(self._url, self._session).create()
        return self

    async def close(self):
        if self._api:
            await self._api.close()

    @property
    def api(self) -> Connection:
        if self._api:
            return self._api
        raise ConnectionError()

    @property
    def password(self) -> str:
        return self._password

    @property
    def url(self) -> str:
        return self._url

    @property
    def pause_time(self) -> int:
        return self._pause_time

    @pause_time.setter
    def pause_time(self, pause_time: int):
        self._pause_time = pause_time

    @property
    def last_logout(self) -> datetime | None:
        return self._last_logout

    @last_logout.setter
    def last_logout(self, last_logout: datetime | None):
        self._last_logout = last_logout

    @need_auth
    async def get_secure_status(self):
        return await self.api.get(self._SECURE_STATUS_DATA, auth=True)

    @need_auth
    async def get_phone_handler(self):
        return await self.api.get(self._IP_PHONE_HANDLER_DATA, auth=True)

    async def get_router(self):
        return await self.api.get(self._ROUTER_DATA)

    async def get_status(self):
        return await self.api.get(self._STATUS_DATA)

    async def get_devices(self):
        return await self.api.get(self._DEVICES_DATA)

    async def get_login(self):
        return await self.api.get(self._LOGIN_DATA)

    @need_auth
    async def get_ip_data(self):
        return await self.api.get(self._IP_DATA, referer=self._IP_REFERER, auth=True)

    @need_auth
    async def get_wps_state(self):
        return await self.api.get(self._WPS_DATA, referer=self._WPS_REFERRER)

    @need_auth
    async def get_phone_calls(self):
        return await self.api.get(self._PHONE_CALLS_DATA, referer=self._PHONE_CALLS_REFERRER, auth=True)

    @need_auth
    async def set_wifi(self, status=True, guest=False, office=False):
        """Set wifi on/off"""
        extra = "guest" if guest else "office" if office else ""
        _LOGGER.info(
            "Turn %s %s wifi...", ["off", "on"][bool(status)], extra if extra else ""
        )
        data = (
            {f"wlan_{extra}_active": str(int(status))}
            if extra
            else {"use_wlan": str(int(status))}
        )
        referer = f"html/content/network/wlan_{extra if extra else 'basic'}.html"
        return await self.api.post(
            f"data/{'WLANBasic' if extra else 'Modules'}.json", data, referer
        )

    @need_auth
    async def wps_on(self):
        _LOGGER.info("Enable wps connect...")
        await self.api.post(
            self._WPS_CHANGE_DATA,
            {"wlan_add": "on", "wps_key": "connect"},
            self._WPS_CHANGE_REFERRER,
        )

    @need_auth
    async def reconnect(self):
        _LOGGER.info("Reconnect with internet provider...")
        await self.api.post(
            self._RECONNECT_DATA,
            {"req_connect": "reconnect"},
            self._RECONNECT_REFERRER,
        )

    @need_auth
    async def reboot(self):
        _LOGGER.info("Reboot speedport...")
        await self.api.post(
            self._REBOOT_DATA,
            {"reboot_device": "true"},
            self._REBOOT_REFERRER,
        )

    async def login(self, password=""):
        return await self.api.login(password or self.password)


class SpeedportSmart4Api(SpeedportApi):
    pass


class SpeedportSmart3Api(SpeedportApi):
    _IP_REFERER = "html/content/internet/connection.html"
    _IP_DATA = "data/INetIP.json"

    _PHONE_CALLS_REFERRER = "html/content/phone/phone_call_list.html"

    _RECONNECT_REFERRER = "html/content/internet/connection.html"
    _RECONNECT_DATA = "data/INetIP.json"

    _REBOOT_REFERRER = "html/content/config/problem_handling.html"
