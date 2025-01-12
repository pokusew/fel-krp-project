// 8.2. Status codes
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#error-responses
// Note that the error codes in the range 0x01 - 0x0B and the error code 0x7F
// are also used in the CTAPHID layer; see the definition in 11.2.9.1.6. CTAPHID_ERROR (0x3F)
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-hid-error
#define CTAP1_ERR_SUCCESS                   0x00 // Indicates successful response.
#define CTAP2_OK                            CTAP1_ERR_SUCCESS
#define CTAP1_ERR_INVALID_COMMAND           0x01 // The command is not a valid CTAP command.
#define CTAP1_ERR_INVALID_PARAMETER         0x02 // The command included an invalid parameter.
#define CTAP1_ERR_INVALID_LENGTH            0x03 // Invalid message or item length.
#define CTAP1_ERR_INVALID_SEQ               0x04 // Invalid message sequencing.
#define CTAP1_ERR_TIMEOUT                   0x05 // Message timed out.
#define CTAP1_ERR_CHANNEL_BUSY              0x06 // Channel busy. Client SHOULD retry the request after a short delay. Note that the client MAY abort the transaction if the command is no longer relevant.
#define CTAP1_ERR_LOCK_REQUIRED             0x0A // Command requires channel lock.
#define CTAP1_ERR_INVALID_CHANNEL           0x0B // Command not allowed on this cid.
#define CTAP2_ERR_CBOR_PARSING              0x10 // TODO(pokusew): this is not in the current spec
#define CTAP2_ERR_CBOR_UNEXPECTED_TYPE      0x11 // Invalid/unexpected CBOR error.
#define CTAP2_ERR_INVALID_CBOR              0x12 // Error when parsing CBOR.
#define CTAP2_ERR_INVALID_CBOR_TYPE         0x13 // TODO(pokusew): this is not in the current spec
#define CTAP2_ERR_MISSING_PARAMETER         0x14 // Missing non-optional parameter.
#define CTAP2_ERR_LIMIT_EXCEEDED            0x15 // Limit for number of items exceeded.
#define CTAP2_ERR_FP_DATABASE_FULL          0x17 // Fingerprint data base is full, e.g., during enrollment.
#define CTAP2_ERR_LARGE_BLOB_STORAGE_FULL   0x18 // Large blob storage is full. (See 6.10.3 Large, per-credential blobs.)
#define CTAP2_ERR_CREDENTIAL_EXCLUDED       0x19 // Valid credential found in the exclude list.
#define CTAP2_ERR_CREDENTIAL_NOT_VALID      0x20 // TODO(pokusew): this is not in the current spec
#define CTAP2_ERR_PROCESSING                0x21 // Processing (Lengthy operation is in progress).
#define CTAP2_ERR_INVALID_CREDENTIAL        0x22 // Credential not valid for the authenticator.
#define CTAP2_ERR_USER_ACTION_PENDING       0x23 // Authentication is waiting for user interaction.
#define CTAP2_ERR_OPERATION_PENDING         0x24 // Processing, lengthy operation is in progress.
#define CTAP2_ERR_NO_OPERATIONS             0x25 // No request is pending.
#define CTAP2_ERR_UNSUPPORTED_ALGORITHM     0x26 // Authenticator does not support requested algorithm.
#define CTAP2_ERR_OPERATION_DENIED          0x27 // Not authorized for requested operation.
#define CTAP2_ERR_KEY_STORE_FULL            0x28 // Internal key storage is full.
#define CTAP2_ERR_UNSUPPORTED_OPTION        0x2B // Unsupported option.
#define CTAP2_ERR_INVALID_OPTION            0x2C // Not a valid option for current operation.
#define CTAP2_ERR_KEEPALIVE_CANCEL          0x2D // Pending keep alive was cancelled.
#define CTAP2_ERR_NO_CREDENTIALS            0x2E // No valid credentials provided.
#define CTAP2_ERR_USER_ACTION_TIMEOUT       0x2F // A user action timeout occurred.
#define CTAP2_ERR_NOT_ALLOWED               0x30 // Continuation command, such as, authenticatorGetNextAssertion not allowed.
#define CTAP2_ERR_PIN_INVALID               0x31 // PIN Invalid.
#define CTAP2_ERR_PIN_BLOCKED               0x32 // PIN Blocked.
#define CTAP2_ERR_PIN_AUTH_INVALID          0x33 // PIN authentication,pinUvAuthParam, verification failed.
#define CTAP2_ERR_PIN_AUTH_BLOCKED          0x34 // PIN authentication using pinUvAuthToken blocked. Requires power cycle to reset.
#define CTAP2_ERR_PIN_NOT_SET               0x35 // No PIN has been set.
#define CTAP2_ERR_PUAT_REQUIRED             0x36 // A pinUvAuthToken is required for the selected operation. See also the pinUvAuthToken option ID.
#define CTAP2_ERR_PIN_POLICY_VIOLATION      0x37 // PIN policy violation. Currently only enforces minimum length.
#define CTAP2_ERR_RESERVED_0x38             0x38 // Reserved for Future Use
#define CTAP2_ERR_REQUEST_TOO_LARGE         0x39 // Authenticator cannot handle this request due to memory constraints.
#define CTAP2_ERR_ACTION_TIMEOUT            0x3A // The current operation has timed out.
#define CTAP2_ERR_UP_REQUIRED               0x3B // User presence is required for the requested operation.
#define CTAP2_ERR_UV_BLOCKED                0x3C // built-in user verification is disabled.
#define CTAP2_ERR_INTEGRITY_FAILURE         0x3D // A checksum did not match.
#define CTAP2_ERR_INVALID_SUBCOMMAND        0x3E // The requested subcommand is either invalid or not implemented.
#define CTAP2_ERR_UV_INVALID                0x3F // built-in user verification unsuccessful. The platform SHOULD retry.
#define CTAP2_ERR_UNAUTHORIZED_PERMISSION   0x40 // The permissions parameter contains an unauthorized permission.
#define CTAP1_ERR_OTHER                     0x7F // Other unspecified error.
#define CTAP2_ERR_SPEC_LAST                 0xDF // CTAP 2 spec last error.
#define CTAP2_ERR_EXTENSION_FIRST           0xE0 // Extension specific error.
#define CTAP2_ERR_EXTENSION_LAST            0xEF // Extension specific error.
#define CTAP2_ERR_VENDOR_FIRST              0xF0 // Vendor specific error.
#define CTAP2_ERR_VENDOR_LAST               0xFF // Vendor specific error.
