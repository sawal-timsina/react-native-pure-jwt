
#import "RNPureJwt.h"
#import "JWT.h"

@implementation RNPureJwt

- (dispatch_queue_t)methodQueue
{
    return dispatch_get_main_queue();
}
RCT_EXPORT_MODULE()

RCT_REMAP_METHOD(sign,
                 claims: (NSDictionary *) claims
                 secret: (NSString *) secret
                 options: (NSDictionary *) options
                 resolver: (RCTPromiseResolveBlock) resolve
                 rejecter: (RCTPromiseRejectBlock) reject
                ) {
    JWTClaimsSet *claimsSet = [[JWTClaimsSet alloc] init];

    NSMutableDictionary *payload = [[NSMutableDictionary alloc] init];

    for(id key in claims) {
        if([key isEqualToString: @"aud"]) {
            claimsSet.audience = [claims objectForKey:key];
        } else if([key isEqualToString: @"jti"]) {
            claimsSet.identifier = [claims objectForKey:key];
        } else if([key isEqualToString: @"iss"]) {
            claimsSet.issuer = [claims objectForKey:key];
        } else if([key isEqualToString: @"sub"]) {
            claimsSet.subject = [claims objectForKey:key];
        } else if([key isEqualToString: @"typ"]) {
            claimsSet.type = [claims objectForKey:key];
        } else if([key isEqualToString: @"iat"]) {
            NSInteger issuedAt = [[claims objectForKey:key] integerValue] / 1000;
            claimsSet.issuedAt = [NSDate dateWithTimeIntervalSince1970: issuedAt];
        } else if([key isEqualToString: @"nbf"]) {
            NSInteger notBeforeDate = [[claims objectForKey:key] integerValue] / 1000;
            claimsSet.notBeforeDate = [NSDate dateWithTimeIntervalSince1970: notBeforeDate];
        } else if([key isEqualToString: @"exp"]) {
            NSInteger expirationDate = [[claims objectForKey:key] integerValue] / 1000;
            claimsSet.expirationDate = [NSDate dateWithTimeIntervalSince1970: expirationDate];
        } else {
            [payload setObject: [claims objectForKey:key] forKey: key];
        }
    }

    JWTEncodingBuilder *builder = [JWTEncodingBuilder encodePayload:payload];

    NSString *algorithmName = options[@"alg"] ? options[@"alg"] : @"HS256";
    id holder = [JWTAlgorithmHSFamilyDataHolder new].algorithmName(algorithmName).secret(secret);
    JWTCodingResultType *result = builder.claimsSet(claimsSet).addHolder(holder).result;

    if(result.successResult) {
        resolve(result.successResult.encoded);
    } else {
        reject(@"failed", @"Encoding failed", result.errorResult.error);
    }
}

@end

