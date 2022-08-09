import {NativeModules} from 'react-native'

const {RNPureJwt} = NativeModules

export const sign = (token, secret, options = {}) =>
    RNPureJwt.sign(token, secret, options)
