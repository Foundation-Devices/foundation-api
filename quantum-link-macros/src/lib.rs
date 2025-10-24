use proc_macro::TokenStream;
use quote::quote;
use syn::DeriveInput;

#[proc_macro_attribute]
pub fn quantum_link(_metadata: TokenStream, input: TokenStream) -> TokenStream {
    let input: DeriveInput = syn::parse(input).unwrap();

    let expanded = quote! {
        #[derive(Clone, Debug)]
        #[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
        #[derive(minicbor_derive::Encode, minicbor_derive::Decode)]
        #[flutter_rust_bridge::frb(non_opaque)]
        #input
    };

    TokenStream::from(expanded)
}
