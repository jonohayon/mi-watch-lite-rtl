Getting the firmware
===

# Goals
 - Find out how to download a firmware for a device
 - Learn how to use new tools (for example, Frida)
 - Nice to have - learn about the API, see if there's anything relevant for my usage

# Research
I'm using the iOS 'Mi Wear' app to configure the device and update its firmware. Therefore, that's where I started.

## HTTP interception
I used mitmproxy in order to intercept the HTTP traffic of the app. It seems that most of the requests are made to the
`sg.hlth.io.mi.com` domain, at lest the ones made to interesting routes (such as `/healthapp/device/deviceinfo`). As it
seems, all requests' to this domain have the same body structure:
```
_nonce:     /////+7Yj1oBoGvD
data:       J7HDQ/ofL18EfakGihfF+FjDG53/d/1gC+yNKOPl1oYi9HH+qkUPDrg5iu9yRrGFcbH6w/J1xBfKza9A2eWdAowqDYqaSo+Sj81S25RrT5gQP5fGteOj+1gAmXVTaToreMWyJ6IIIZ0iy+4IfA==
rc4_hash__: Nx4JoWdyI3cr5dYKOZKcLtpH2ayWuU0BcLjS6Q==
signature:  sWoZ4MMWiJtgvMGS7uyOsi+oGz4=
```
Some requests don't include the `data` field. Moreover, all requests use the POST method. All data seems to be base64
encoded.

A request to `https://sg.hlth.io.mi.com/healthapp/user/get_miot_user_profile` withtout data:
```
_nonce:     +Fz0DnLaVV0BoGvc
rc4_hash__: q1VgQt+v0s5HNjY6XkztutsEHWbRowbYomyvaw==
signature:  ig1/UJUKTOEH/j4RZCoGvu0nha4=
```

The response seems to be encrypted and base64-encoded:
```
5gdQX/CNh7keVVElSFSqiIUtWmnclh+0vXq+M8Q7wPRQKpobgbkKLXW0cUm+ogMeV5GCpWdEghzeKvfYFYCuGmm1A4MDbyxaMLnz4V1L8KyY6kObp9RLpAslRTGvCphpMVZtzQvE7rXG0Ys449HeHDtxNK41QECa1vwzVx/w/ejJ8/sz8JLQQKVjaHxxZRP4+kb/k0GQKoJSVvWBWz7gnpAOQgcR3Q/3v7xi5vuVWuUJG/xAWpq/znttViXQbeQobjUTs1U6+krCENj5EZ2WMFSl5dPke9jA27vSYIi7p+YitJ5ie7stA9cMvlKsryoiK27yuIQIjsnVHK77FnACbKmOEnXDAlgGDovGGuOuJopgHdp5YXH8yyTarphMZqP6eURdl+tCgQ/0PY2VzvRMddM/VIPfS9/0od7g2OiQrigDFxczoYW0a3lBYaf6ckThADcuJaO6
```

In order to find out how the request data is encrypted and how the response data is encrypted I started to analyze the
Xiaomi Wear Android app (since it decompiles easier than an iOS app and the APK is available on Google).

## Android API communications
I used `jadx` to decompile an APK I found online of Xiaomi Wear. After the decompilation was successful, and it didn't
seem that Xiaomi used any deobfuscations on the code, I decided to first look for the string `rc4_hash__`, thinking it
would be unique enough to be featured in the cipher mechanism.

Indeed, the only place in the code of the app this string is featured in is the `CloudUtil.java` file in the
`com.xiaomi.common.crypt` package.
This code includes both the encryption and serialization logic of the HTTP requests done by the app. There seem to be
three main methods of interest - `decryptResponse`, `encryptParams` and `encryptParams2`. Indeed, as I was thinking, it
looks as if the key for decrypting each request is given in the request itself (as RC4 is symmetric, and either had to
share the key with the backend or send it along the request, rendering the encryption useless).

Update: I was actually incorrect, as it turns out. Looking on the request interceptor (`CloudInterceptor.java` file from
the `com.xiaomi.miot.core.api.interceptor` package), the method `CloudUtil::decryptResponse` is called with the nonce
that was generated for the request and an account-specific `ssecurity` (from now on I'll refer to it as the "account
security token"). In pseudo-code, what `decryptResponse` does is as follows:
```python
def decryptResponse(body: str, ssecurity: str, nonce: str)
  decodedBody = base64.decode(body)
  decodedSecurityToken = base64.decode(ssecurity)
  decodedNonce = base64.decode(nonce)

  key = sha56(decodedSecurityToken + decodedNonce)
  return rc4.decrypt(decodedBody, key)
```

Which means that the key isn't actually sent out with each request, but rather uses an account-specific key that's
generated every x minutes (it requires a refresh).
Moreover, looking on the interceptor showed the difference between `CloudUtil::encryptParams` and
`CloudUtil::encryptParams2`:
```java
private Map<String, String> getEncryptedParams(String str, String str2, Map<String, String> map, String str3, String str4) throws Exception {
    if (this.mCloudSecretProvider.encryptResponse()) {
        return CloudUtil.encryptParams(str, str2, map, str3, str4);
    }
    return CloudUtil.encryptParams2(str2, map, str3, str4);
}
```

Problem now - how do I find this account security token? Genymotion and mitmproxy again to the rescue!

### Live-analyzation of the android app

> Xiaomi user details: 3k26pnz0@freeml.net:Password1!

I used Genymotion to run this Android app, and used mitmproxy to sniff the HTTPS traffic from the app during the login
sequence (didn't want to log out from the app on my iPhone). After getting stuck on machine setup, I finally setup the
root CA of mitmproxy and successfully was able to run the Xiaomi app on the VM.

References for future notice:
 - I used this package to enable ARM code to run on the VM: https://github.com/m9rco/Genymotion_ARM_Translation
 - And this app to install the root CA on the rooted Genymotion machine: https://play.google.com/store/apps/details?id=net.jolivier.cert.Importer

The login button sends a POST request to `https://account.xiaomi.com/pass/serviceLoginAuth2` with the following data:
```
cc:       +1
qs:       %3F_json%3Dtrue%26sid%3Dmiothealth%26_locale%3Den_US
callback: https://sts-hlth.io.mi.com/healthapp/sts
_json:    true
_sign:    4142j+w4uzuhK8Pl3QTtweBideU=
user:     3k26pnz0@freeml.net
hash:     0CEF1FB10F60529028A71F58E54ED07B
sid:      miothealth
_locale:  en_US
```

The MIME type of the content is `application/x-www-form-urlencoded`. The hash seems to be a simple MD5 hash of the
password (from `md5hashgenerator.com`: `0CEF1FB10F60529028A71F58E54ED07B`, which is the same). The response looks pretty
odd and nonstandard:
```
&&&START&&&{"qs":"%3F_json%3Dtrue%26sid%3Dmiothealth%26_locale%3Den_US","ssecurity":"TL3AiHnzgzVA1Elr6ipYxA==","code":0,"passToken":"V1:DXmurwq2/R1BHTELu6obCQVHxWGNoF6R2taHdpsmVh2kTdZ+F23hd9Tmz18vje+1JShdaeEEwCpZhCgIZAKfS1JaIKa6oQFnkZkdXknU4VSDDlG2hbvOnElQSOq0qECQ1Jtjne0vzXtyBWCluh0N5las6pnjqcKGvFEQGf2NN/3pe5HYJA6PKpy15jQy9l3XETc3rUXGZHBSdyotAHJs0dTl7ClMeBE99/6e540SzUOEqccxWUGlH1/Ijr48pytpUC9ID0lOi8jNmnDnZ2fyn9pCOvqAvUxju8PNJ7o8GfU=","description":"\xe6\x88\x90\xe5\x8a\x9f","securityStatus":0,"nonce":8661093188422538240,"userId":6529024931,"cUserId":"7C_iaq5VYHBYBj-V_EJzjRsgQl0","result":"ok","psecurity":"3iQNfnDZy/1BjbJ2/XLczw==","captchaUrl":null,"location":"https://sts-hlth.io.mi.com/healthapp/sts?d=an_ca3e1cfc4d5f5c663f49ccd96ae89f08&ticket=0&pwd=1&p_ts=1639085951000&fid=0&p_lm=1&auth=Yqq3OubK%2BkmVzbe5tLqNROtGpu6Zb9H25EZVYf1Kv4KxRMLybRwMCeiuOxNoy4ZatDucEWP1MNBYk9VUYvs5%2BEk9LtSTGjGHsHcfA%2B7XXXaBnmwXvQZmz5vB%2B1TxiU%2FqLECiAB4urL2GdjuN3Ba4aI2%2FDbA0kfF9kYxWjDRYNKg%3D&m=1&tsl=0&nonce=5z3T4ZhL7ucBoNdT&_ssign=WvZ%2BEyHZg4L2%2Fi8Z60gd%2FWO5Ckw%3D","pwd":1,"desc":"\xe6\x88\x90\xe5\x8a\x9f"}
```

Removing the `&&&START&&` prefix and prettifying the JSON:
```json
{
    "qs": "%3F_json%3Dtrue%26sid%3Dmiothealth%26_locale%3Den_US",
    "ssecurity": "TL3AiHnzgzVA1Elr6ipYxA==",
    "code": 0,
    "passToken": "V1:DXmurwq2/R1BHTELu6obCQVHxWGNoF6R2taHdpsmVh2kTdZ+F23hd9Tmz18vje+1JShdaeEEwCpZhCgIZAKfS1JaIKa6oQFnkZkdXknU4VSDDlG2hbvOnElQSOq0qECQ1Jtjne0vzXtyBWCluh0N5las6pnjqcKGvFEQGf2NN/3pe5HYJA6PKpy15jQy9l3XETc3rUXGZHBSdyotAHJs0dTl7ClMeBE99/6e540SzUOEqccxWUGlH1/Ijr48pytpUC9ID0lOi8jNmnDnZ2fyn9pCOvqAvUxju8PNJ7o8GfU=",
    "description": "\u6210\u529f",
    "securityStatus": 0,
    "nonce": 8661093188422538240,
    "userId": 6529024931,
    "cUserId": "7C_iaq5VYHBYBj-V_EJzjRsgQl0",
    "result": "ok",
    "psecurity": "3iQNfnDZy/1BjbJ2/XLczw==",
    "captchaUrl": null,
    "location": "https://sts-hlth.io.mi.com/healthapp/sts?d=an_ca3e1cfc4d5f5c663f49ccd96ae89f08&ticket=0&pwd=1&p_ts=1639085951000&fid=0&p_lm=1&auth=Yqq3OubK%2BkmVzbe5tLqNROtGpu6Zb9H25EZVYf1Kv4KxRMLybRwMCeiuOxNoy4ZatDucEWP1MNBYk9VUYvs5%2BEk9LtSTGjGHsHcfA%2B7XXXaBnmwXvQZmz5vB%2B1TxiU%2FqLECiAB4urL2GdjuN3Ba4aI2%2FDbA0kfF9kYxWjDRYNKg%3D&m=1&tsl=0&nonce=5z3T4ZhL7ucBoNdT&_ssign=WvZ%2BEyHZg4L2%2Fi8Z60gd%2FWO5Ckw%3D",
    "pwd": 1,
    "desc": "\u6210\u529f"
}
```

And looks like we got our ssecurity :) But does it change every time? Instead of looking on this subject I decided to
try and decrypt a POST request made to `https://hlth.io.mi.com/healthapp/mipush/reg` using the ssecurity I extracted
before. _This didn't work!_ Since I didn't know what caused this to fail, and I thought the ssecurity token might be the
cause (since all the other parameters matched the ones sent in the specific request), I decided to change direction
and use Frida to put hooks on the encryption functions.

### Hooking and live debugging using Frida
After some struggling, I setup Frida on the Genymotion emulator and was able to hook the relevant function and view its
parameters.

Using Frida really freed my research, as it meant I could setup a simple HTTP hooking interface in JS, and write my
hooks in Python - for example, hooking on a specific route with specific HTTP method. These hooks can be seen in
`research/hooks-server.js`.

In the `Xiaomi Wear` app, each request-response pair is identified by a randomly generated nonce that's sent with the
request to the server and is used to encrypt the response data. Therefore, a mapping of nonce to req+res pair was
required. This is managed using the `HookManager` class, and specific hooks are added using the `hook` decorator.
There's a default general hook installed (can be enabled/disabled using the `set_verbosity` function) that prints the
request data to the screen.

As I noticed all interesting communication is actually encrypted, I only needed to hook `CloudUtil::encryptParams` in
order to look on the traffic, which is what the Frida script actually does. In order to use the hooks, run the following
from the top-level of this project:
```bash
python3 -m research.hooks research/hooks-server.js
```

This will setup the Python hooks and start the Frida script on the Genymotion device (or an actual Android device
connected via USB).

### Finding the firmware download code
Now that I had a proper infrastructure to hook into HTTP methods, I wanted to find the code that's in charge of
downloading the firmware update. As I said before, my device requires a firmware update, but for some reason the app
won't actually update it, so I could test the download feature using it (I got a physical device to test this on, a Moto
X Play XT1562 with Android 7.1.1).

It's worth noting that the Xiaomi app supports a _lot_ of wearable devices, which are divided by the app into three
categories - BLE devices, Huami devices and Wear OS devices. Wear OS is the name of Android for wearables, and BLE
means that the device uses a proprietary Xiaomi protocol and is based on a Nordic Semiconductors BLE chip (such as the
common nRF52840). I have no idea what Huami means, but google says it's one of Xiaomi's manufacturing subsidiaries.

Trying to update the firmware from the Android app failed for some reason, posting a toast with the message "Couldn't
obtain the firmware version". Looking for this string in the app's code resulted in the resource id `firmware_check_version_failed`
which is used in 4 places - two times in the class `com.xiaomi.wearable.home.devices.ble.page.BleSettingItemsFragment`
and two in `com.xiaomi.wearable.home.devices.ble.setting.ui.BleSettingItemsFragment`, both of which seem to include
pretty much the same code. I was pleased to find that all of them essentially resulted in something like this:
```java
Bundle bundle = new Bundle();
bundle.putSerializable(BaseFragment.KEY_PARAM1, latestVersion);
bundle.putString(BaseFragment.KEY_PARAM2, this.f.getDid());
bundle.putBoolean(BleUpdateFragment.j, z2);
gotoPage(BleUpdateFragment.class, bundle, false);
```

Cleaning up the code:
```java
Bundle bundle = new Bundle();
bundle.putSerializable("key_param1", latestVersion);
bundle.putString("key_param2", this.bluetoothDevice.getDid());
bundle.putBoolean("key_store_mdoe", storeMode);
gotoPage(BleUpdateFragment.class, bundle, false);
```

Looking on the `BleUpdateFragment` class, I was able to split the "firmware update" process into two distinct processes,
both of which need to be researched:
 - The firmware download process, which is what I've been researching so far
 - The firmware _sync_ process, which is the flow that uploads the downloaded firmware onto the device via Bluetooth.
   I still didn't start to research this, but I'm looking on relevant stuff while researching the network part of the
   process.
Other than that the fragment class didn't give me a lot of information unfortunately.
