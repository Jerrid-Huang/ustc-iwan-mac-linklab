/* Minimal probe for Security.framework linking.
 * Uses CF + SecItem symbols and prints the result; exit 0 either way
 * (this is a link probe, not a behavior test). */
#include <stdio.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

static CFDictionaryRef makeq(void)
{
    const void *keys[] = {
        kSecClass, kSecAttrService, kSecAttrAccount,
        kSecValueData, kSecReturnData, kSecAttrAccessible
    };
    const void *vals[] = {
        kSecClassGenericPassword, CFSTR("srv"), CFSTR("acct"),
        CFSTR("x"), kCFBooleanTrue,
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    };
    return CFDictionaryCreate(NULL, keys, vals, 6,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
}

int main(void)
{
    CFTypeRef res = NULL;
    OSStatus st = SecItemCopyMatching(makeq(), &res);
    printf("SecItemCopyMatching st=%d\n", (int)st);
    if (res)
        CFRelease(res);
    return 0;
}
