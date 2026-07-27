//! Contract types shared by node, storage, and API layers.

pub mod hosting;

pub use hosting::{
    HostingContractError, HostingContractState, OperatorHostingContract, OperatorHostingPayment,
    OperatorHostingPaymentDirection,
};
