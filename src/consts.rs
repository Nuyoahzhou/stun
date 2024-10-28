

use std::collections::HashMap;
pub const DEFAULT_SERVER_ADDR:&str  = "stun.ekiga.net:3478";

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
enum NAT {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
          println!("{:?}", *NAT_STR.get(&NAT::NATFull).unwrap());
    println!("{:?}", *BEHAVIOR_TYPE_STR.get(&Behavior::BehaviorTypeEndpoint).unwrap());
    println!("{:?}", *NAT_NORMAL_TYPE_STR.get(&NATBehavior {
        mapping_type: Behavior::BehaviorTypeEndpoint as i32,
        filtering_type: Behavior::BehaviorTypeEndpoint as i32,
    }).unwrap());
    }


}

