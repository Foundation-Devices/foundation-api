use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(QuantumLinkMessage)]
pub fn derive_quantum_link_message(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let expanded = quote! {
        impl QuantumLinkMessage<#name> for #name {}
    };

    TokenStream::from(expanded)
}
