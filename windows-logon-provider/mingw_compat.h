/* Compatibility for building the Microsoft Credential Provider sample with MinGW-w64. */
#pragma once
// Parse the standard library before defining Microsoft's legacy __in/__out annotations.
#include <atomic>
#include <algorithm>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#ifndef __in
#define __in
#define __out
#define __in_opt
#define __out_opt
#define __inout
#define __deref_out
#define __deref_out_opt
#define __override
#endif

#ifndef CRED_PACK_PROTECTED_CREDENTIALS
#define CRED_PACK_PROTECTED_CREDENTIALS 0x1
#endif
#ifndef CRED_PACK_WOW_BUFFER
#define CRED_PACK_WOW_BUFFER 0x2
#endif
#ifndef CRED_PACK_GENERIC_CREDENTIALS
#define CRED_PACK_GENERIC_CREDENTIALS 0x4
#endif
#ifndef CRED_PACK_ID_PROVIDER_CREDENTIALS
#define CRED_PACK_ID_PROVIDER_CREDENTIALS 0x8
#endif
