use {proc_macro::TokenStream, quote::quote, syn::DeriveInput};

#[proc_macro_attribute]
pub fn quantum_link(_metadata: TokenStream, input: TokenStream) -> TokenStream {
    let input: DeriveInput = syn::parse(input).unwrap();
    let name = input.ident.clone();

    let expanded = quote! {
        #[derive(Clone, Debug, Encode, Decode, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
        #[frb(non_opaque)]
        #input
        impl QuantumLink<#name> for #name {}
    };

    TokenStream::from(expanded)
}
