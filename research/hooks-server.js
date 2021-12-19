const CRYPT_PACKAGE_NAME = 'com.xiaomi.common.crypt'
const CRYPT_CLASS_NAME = 'CloudUtil'

const getCloudUtil = (
  packageName = CRYPT_PACKAGE_NAME,
  className = CRYPT_CLASS_NAME
) => {
  return Java.use(`${packageName}.${className}`)
}

const JavaString = Java.use('java.lang.String')

const DATA_KEY = JavaString.$new('data')

const DATA_TYPES = {
  REQUEST: 'request',
  RESPONSE: 'response'
}

/**
 * @param {string} nonce
 * @param {DATA_TYPES} type
 * @param {object} data
 */
const sendData = (nonce, type, data) => {
  const content = { nonce, type, ...data }
  send(JSON.stringify(content))
}

/**
 * @description Hook for the com.xiaomi.common.crypt.CloudUtil::encryptParams function. Receives its original arguments
 * from Frida and logs them.
 * @param {string} method The HTTP method of the current request.
 * @param {string} route The route requested in this request.
 * @param {object} dataHashMap The request body.
 * @param {string} nonce base64-encoded nonce data used to encrypt the parameters in the original code.
 * @param {string} ssecurity base64-encoded security token, one per user login.
 */
const encryptParamsHook = (method, route, dataHashMap, nonce, ssecurity) => {
  const requestBodyObject = Java.cast(dataHashMap.get(DATA_KEY), JavaString)
  const body = String(requestBodyObject)
  const requestData = { method, route, ssecurity, body }
  sendData(nonce, DATA_TYPES.REQUEST, requestData)
}

const encryptParams2Hook = console.log

const decryptResponseHook = (decryptedContent, nonce, ssecurity) => {
  const responseData = { ssecurity, body: decryptedContent }
  sendData(nonce, DATA_TYPES.RESPONSE, responseData)
}

/**
 * @description Places hooks on a given CloudUtil type functions.
 */
const hookCloudUtil = CloudUtil => {
  CloudUtil.encryptParams.implementation = function () {
    encryptParamsHook(...arguments)
    return this.encryptParams(...arguments)
  }

  CloudUtil.encryptParams2.implementation = function () {
    enryptedParams2Hook(...arguments)
    return this.encryptParams2(...arguments)
  }

  CloudUtil.decryptResponse.implementation = function () {
    const decryptedContent = this.decryptResponse(...arguments)
    const otherArguments = [].slice.apply(arguments, [1])
    decryptResponseHook(decryptedContent, ...otherArguments)
    return decryptedContent
  }
}

Java.perform(() => {
  const cloudUtilClass = getCloudUtil()
  hookCloudUtil(cloudUtilClass)
})
