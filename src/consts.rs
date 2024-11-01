use std::collections::HashMap;
pub const DEFAULT_SERVER_ADDR: &str = "stun.ekiga.net:3478";

pub const MAGIC_COOKIE: u32 = 0x2112A442;
pub const FINGERPRINT: u32 = 0x5354554E;

// BehaviorType is NAT behavior type.
type BehaviorType = i32;

// NATBehavior is NAT behavior type of MappingType and FilteringType.
#[derive(Debug, PartialEq, Eq, Hash)]
struct NATBehavior {
    mapping_type: BehaviorType,
    filtering_type: BehaviorType,
}

// NAT types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NAT {
    NATError,
    NATUnknown,
    NATNone,
    NATBlocked,
    NATFull,
    NATSymmetric,
    NATRestricted,
    NATPortRestricted,
    SymmetricUDPFirewall,

    // Deprecated spellings of these constants
    NATSymetric,
    NATSymetricUDPFirewall,
    NATSymmetricUDPFirewall,
}

// Behavior types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Behavior {
    BehaviorTypeUnknown,
    BehaviorTypeEndpoint,
    BehaviorTypeAddr,
    BehaviorTypeAddrAndPort,
}

lazy_static! {
    static ref NAT_STR: HashMap<NAT, &'static str> = {
        let mut m = HashMap::new();
        m.insert(NAT::NATError, "Test failed");
        m.insert(NAT::NATUnknown, "Unexpected response from the STUN server");
        m.insert(NAT::NATBlocked, "UDP is blocked");
        m.insert(NAT::NATFull, "Full cone NAT");
        m.insert(NAT::NATSymmetric, "Symmetric NAT");
        m.insert(NAT::NATRestricted, "Restricted NAT");
        m.insert(NAT::NATPortRestricted, "Port restricted NAT");
        m.insert(NAT::NATNone, "Not behind a NAT");
        m.insert(NAT::SymmetricUDPFirewall, "Symmetric UDP firewall");
        // Insert deprecated spellings
        m.insert(NAT::NATSymetric, "Symmetric NAT");
        m.insert(NAT::NATSymetricUDPFirewall, "Symmetric UDP firewall");
        m.insert(NAT::NATSymmetricUDPFirewall, "Symmetric UDP firewall");
        m
    };

    static ref BEHAVIOR_TYPE_STR: HashMap<Behavior, &'static str> = {
        let mut m = HashMap::new();
        m.insert(Behavior::BehaviorTypeUnknown, "Unknown");
        m.insert(Behavior::BehaviorTypeEndpoint, "EndpointIndependent");
        m.insert(Behavior::BehaviorTypeAddr, "AddressDependent");
        m.insert(Behavior::BehaviorTypeAddrAndPort, "AddressAndPortDependent");
        m
    };

    static ref NAT_NORMAL_TYPE_STR: HashMap<NATBehavior, &'static str> = {
        let mut m = HashMap::new();
        m.insert(NATBehavior {
            mapping_type: Behavior::BehaviorTypeEndpoint as i32,
            filtering_type: Behavior::BehaviorTypeEndpoint as i32,
        }, "Full cone NAT");
        m.insert(NATBehavior {
            mapping_type: Behavior::BehaviorTypeEndpoint as i32,
            filtering_type: Behavior::BehaviorTypeAddr as i32,
        }, "Restricted cone NAT");
        m.insert(NATBehavior {
            mapping_type: Behavior::BehaviorTypeEndpoint as i32,
            filtering_type: Behavior::BehaviorTypeAddrAndPort as i32,
        }, "Port Restricted cone NAT");
        m.insert(NATBehavior {
            mapping_type: Behavior::BehaviorTypeAddrAndPort as i32,
            filtering_type: Behavior::BehaviorTypeAddrAndPort as i32,
        }, "Symmetric NAT");
        m
    };
}

// Error codes
pub const ERROR_TRY_ALTERNATE: u16 = 300;
pub const ERROR_BAD_REQUEST: u16 = 400;
pub const ERROR_UNAUTHORIZED: u16 = 401;
pub const ERROR_UNASSIGNED402: u16 = 402;
pub const ERROR_FORBIDDEN: u16 = 403;
pub const ERROR_UNKNOWN_ATTRIBUTE: u16 = 420;
pub const ERROR_ALLOCATION_MISMATCH: u16 = 437;
pub const ERROR_STALE_NONCE: u16 = 438;
pub const ERROR_UNASSIGNED439: u16 = 439;
pub const ERROR_ADDRESS_FAMILY_NOT_SUPPORTED: u16 = 440;
pub const ERROR_WRONG_CREDENTIALS: u16 = 441;
pub const ERROR_UNSUPPORTED_TRANSPORT_PROTOCOL: u16 = 442;
pub const ERROR_PEER_ADDRESS_FAMILY_MISMATCH: u16 = 443;
pub const ERROR_CONNECTION_ALREADY_EXISTS: u16 = 446;
pub const ERROR_CONNECTION_TIMEOUT_OR_FAILURE: u16 = 447;
pub const ERROR_ALLOCATION_QUOTA_REACHED: u16 = 486;
pub const ERROR_ROLE_CONFLICT: u16 = 487;
pub const ERROR_SERVER_ERROR: u16 = 500;
pub const ERROR_INSUFFICIENT_CAPACITY: u16 = 508;

// Attribute families
pub const ATTRIBUTE_FAMILY_IPV4: u16 = 0x01;
pub const ATTRIBUTE_FAMILY_IPV6: u16 = 0x02;

// Attributes
pub const ATTRIBUTE_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTRIBUTE_RESPONSE_ADDRESS: u16 = 0x0002;
pub const ATTRIBUTE_CHANGE_REQUEST: u16 = 0x0003;
pub const ATTRIBUTE_SOURCE_ADDRESS: u16 = 0x0004;
pub const ATTRIBUTE_CHANGED_ADDRESS: u16 = 0x0005;
pub const ATTRIBUTE_USERNAME: u16 = 0x0006;
pub const ATTRIBUTE_PASSWORD: u16 = 0x0007;
pub const ATTRIBUTE_MESSAGE_INTEGRITY: u16 = 0x0008;
pub const ATTRIBUTE_ERROR_CODE: u16 = 0x0009;
pub const ATTRIBUTE_UNKNOWN_ATTRIBUTES: u16 = 0x000a;
pub const ATTRIBUTE_REFLECTED_FROM: u16 = 0x000b;
pub const ATTRIBUTE_CHANNEL_NUMBER: u16 = 0x000c;
pub const ATTRIBUTE_LIFETIME: u16 = 0x000d;
pub const ATTRIBUTE_BANDWIDTH: u16 = 0x0010;
pub const ATTRIBUTE_XOR_PEER_ADDRESS: u16 = 0x0012;
pub const ATTRIBUTE_DATA: u16 = 0x0013;
pub const ATTRIBUTE_REALM: u16 = 0x0014;
pub const ATTRIBUTE_NONCE: u16 = 0x0015;
pub const ATTRIBUTE_XOR_RELAYED_ADDRESS: u16 = 0x0016;
pub const ATTRIBUTE_REQUESTED_ADDRESS_FAMILY: u16 = 0x0017;
pub const ATTRIBUTE_EVEN_PORT: u16 = 0x0018;
pub const ATTRIBUTE_REQUESTED_TRANSPORT: u16 = 0x0019;
pub const ATTRIBUTE_DONT_FRAGMENT: u16 = 0x001a;
pub const ATTRIBUTE_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const ATTRIBUTE_TIMER_VAL: u16 = 0x0021;
pub const ATTRIBUTE_RESERVATION_TOKEN: u16 = 0x0022;
pub const ATTRIBUTE_PRIORITY: u16 = 0x0024;
pub const ATTRIBUTE_USE_CANDIDATE: u16 = 0x0025;
pub const ATTRIBUTE_PADDING: u16 = 0x0026;
pub const ATTRIBUTE_RESPONSE_PORT: u16 = 0x0027;
pub const ATTRIBUTE_CONNECTION_ID: u16 = 0x002a;
pub const ATTRIBUTE_XOR_MAPPED_ADDRESS_EXP: u16 = 0x8020;
pub const ATTRIBUTE_SOFTWARE: u16 = 0x8022;
pub const ATTRIBUTE_ALTERNATE_SERVER: u16 = 0x8023;
pub const ATTRIBUTE_CACHE_TIMEOUT: u16 = 0x8027;
pub const ATTRIBUTE_FINGERPRINT: u16 = 0x8028;
pub const ATTRIBUTE_ICE_CONTROLLED: u16 = 0x8029;
pub const ATTRIBUTE_ICE_CONTROLLING: u16 = 0x802a;
pub const ATTRIBUTE_RESPONSE_ORIGIN: u16 = 0x802b;
pub const ATTRIBUTE_OTHER_ADDRESS: u16 = 0x802c;
pub const ATTRIBUTE_ECN_CHECK_STUN: u16 = 0x802d;
pub const ATTRIBUTE_CISCO_FLOWDATA: u16 = 0xc000;

// Message types
pub const TYPE_BINDING_REQUEST: u16 = 0x0001;
pub const TYPE_BINDING_RESPONSE: u16 = 0x0101;
pub const TYPE_BINDING_ERROR_RESPONSE: u16 = 0x0111;
pub const TYPE_SHARED_SECRET_REQUEST: u16 = 0x0002;
pub const TYPE_SHARED_SECRET_RESPONSE: u16 = 0x0102;
pub const TYPE_SHARED_ERROR_RESPONSE: u16 = 0x0112;
pub const TYPE_ALLOCATE: u16 = 0x0003;
pub const TYPE_ALLOCATE_RESPONSE: u16 = 0x0103;
pub const TYPE_ALLOCATE_ERROR_RESPONSE: u16 = 0x0113;
pub const TYPE_REFRESH: u16 = 0x0004;
pub const TYPE_REFRESH_RESPONSE: u16 = 0x0104;
pub const TYPE_REFRESH_ERROR_RESPONSE: u16 = 0x0114;
pub const TYPE_SEND: u16 = 0x0006;
pub const TYPE_SEND_RESPONSE: u16 = 0x0106;
pub const TYPE_SEND_ERROR_RESPONSE: u16 = 0x0116;
pub const TYPE_DATA: u16 = 0x0007;
pub const TYPE_DATA_RESPONSE: u16 = 0x0107;
pub const TYPE_DATA_ERROR_RESPONSE: u16 = 0x0117;
pub const TYPE_CREATE_PERMISSION: u16 = 0x0008;
pub const TYPE_CREATE_PERMISSION_RESPONSE: u16 = 0x0108;
pub const TYPE_CREATE_PERMISSION_ERROR_RESPONSE: u16 = 0x0118;
pub const TYPE_CHANNEL_BINDING: u16 = 0x0009;
pub const TYPE_CHANNEL_BINDING_RESPONSE: u16 = 0x0109;
pub const TYPE_CHANNEL_BINDING_ERROR_RESPONSE: u16 = 0x0119;
pub const TYPE_CONNECT: u16 = 0x000a;
pub const TYPE_CONNECT_RESPONSE: u16 = 0x010a;
pub const TYPE_CONNECT_ERROR_RESPONSE: u16 = 0x011a;
pub const TYPE_CONNECTION_BIND: u16 = 0x000b;
pub const TYPE_CONNECTION_BIND_RESPONSE: u16 = 0x010b;
pub const TYPE_CONNECTION_BIND_ERROR_RESPONSE: u16 = 0x011b;
pub const TYPE_CONNECTION_ATTEMPT: u16 = 0x000c;
pub const TYPE_CONNECTION_ATTEMPT_RESPONSE: u16 = 0x010c;
pub const TYPE_CONNECTION_ATTEMPT_ERROR_RESPONSE: u16 = 0x011c;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        println!("{:?}", *NAT_STR.get(&NAT::NATFull).unwrap());
        println!(
            "{:?}",
            *BEHAVIOR_TYPE_STR
                .get(&Behavior::BehaviorTypeEndpoint)
                .unwrap()
        );
        println!(
            "{:?}",
            *NAT_NORMAL_TYPE_STR
                .get(&NATBehavior {
                    mapping_type: Behavior::BehaviorTypeEndpoint as i32,
                    filtering_type: Behavior::BehaviorTypeEndpoint as i32,
                })
                .unwrap()
        );
    }
}
