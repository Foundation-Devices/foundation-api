use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    parse_macro_input, spanned::Spanned, Attribute, Data, DataStruct, DeriveInput, Fields, Lit,
    Meta, Type, Visibility,
};

#[proc_macro_attribute]
pub fn quantum_link(_metadata: TokenStream, input: TokenStream) -> TokenStream {
    let input: DeriveInput = syn::parse(input).unwrap();

    let expanded = quote! {
        #[derive(Clone, Debug, quantum_link_macros::Cbor)]
        #[cfg_attr(feature = "keyos", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
        #[cfg_attr(feature = "envoy", flutter_rust_bridge::frb(non_opaque))]
        #input
    };

    TokenStream::from(expanded)
}

/// derive macro generates
/// - From<T> for CBOR
/// - TryFrom<CBOR> for T
#[proc_macro_derive(Cbor, attributes(n))]
pub fn derive_cbor(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    derive_cbor_impl(input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

fn derive_cbor_impl(input: DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    let generics = &input.generics;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let (into_impl, try_from_impl) = match &input.data {
        Data::Struct(data_struct) => generate_struct_impls(&data_struct.fields, name)?,
        Data::Enum(data_enum) => {
            let into_body = generate_enum_into_cbor(name, &data_enum.variants)?;
            let try_from_body = generate_enum_try_from_cbor(&data_enum.variants)?;
            (into_body, try_from_body)
        }
        Data::Union(data_union) => {
            return Err(syn::Error::new(
                data_union.union_token.span(),
                "unions not supported",
            ));
        }
    };

    // only auto-impl for non-tuple structs
    let cbor_marker_impl = match &input.data {
        Data::Struct(DataStruct {
            fields: Fields::Unnamed(_),
            ..
        }) => quote! {},
        _ => {
            quote! {
                impl #impl_generics crate::CborMarker for #name #ty_generics #where_clause {}
            }
        }
    };

    Ok(quote! {
        impl #impl_generics From<#name #ty_generics> for dcbor::CBOR #where_clause {
            fn from(value: #name #ty_generics) -> dcbor::CBOR {
                #into_impl
            }
        }

        impl #impl_generics TryFrom<dcbor::CBOR> for #name #ty_generics #where_clause {
            type Error = dcbor::Error;

            fn try_from(cbor: dcbor::CBOR) -> dcbor::Result<Self> {
                #try_from_impl
            }
        }

        #cbor_marker_impl
    })
}

//
// struct
//

fn generate_struct_impls(
    fields: &Fields,
    name: &syn::Ident,
) -> syn::Result<(TokenStream2, TokenStream2)> {
    match fields {
        Fields::Named(fields) => {
            let into_body = generate_named_struct_into_cbor(&fields.named)?;
            let try_from_body = generate_named_struct_try_from_cbor(&fields.named)?;
            Ok((into_body, try_from_body))
        }
        Fields::Unnamed(fields) => {
            if fields.unnamed.len() != 1 {
                return Err(syn::Error::new(
                    fields.span(),
                    "only single-field tuple structs (newtypes) are supported",
                ));
            }
            let (into_body, try_from_body) =
                generate_newtype_struct_impls(fields.unnamed.first().unwrap())?;
            Ok((into_body, try_from_body))
        }
        Fields::Unit => Err(syn::Error::new(name.span(), "unit structs not supported")),
    }
}

fn generate_named_struct_into_cbor(
    fields: &syn::punctuated::Punctuated<syn::Field, syn::token::Comma>,
) -> syn::Result<TokenStream2> {
    let mut field_insertions = Vec::new();

    for field in fields {
        let field_name = field.ident.as_ref().unwrap();
        let field_type = &field.ty;
        let index = get_field_index(&field.attrs)
            .ok_or_else(|| syn::Error::new(field.span(), "missing #[n(x)] attribute"))?;

        if let Some(inner) = get_option_inner(field_type) {
            let cbor_value = gen_to_cbor(&inner, quote! { val });
            field_insertions.push(quote! {
                if let Some(val) = value.#field_name {
                    map.insert(dcbor::CBOR::from(#index), #cbor_value);
                }
            });
        } else {
            let insertion = gen_map_insert(index, field_type, quote! { value.#field_name });
            field_insertions.push(insertion);
        }
    }

    Ok(quote! {
        let mut map = dcbor::Map::new();
        #(#field_insertions)*
        dcbor::CBOR::from(map)
    })
}

fn generate_named_struct_try_from_cbor(
    fields: &syn::punctuated::Punctuated<syn::Field, syn::token::Comma>,
) -> syn::Result<TokenStream2> {
    let mut field_extractions = Vec::new();
    let mut field_names = Vec::new();

    for field in fields {
        let field_name = field.ident.as_ref().unwrap();
        let field_type = &field.ty;
        let index = get_field_index(&field.attrs)
            .ok_or_else(|| syn::Error::new(field.span(), "missing #[n(x)] attribute"))?;

        let extraction = if let Some(inner) = get_option_inner(field_type) {
            let value = gen_map_get_optional(index, &inner, quote! { map });
            quote! { let #field_name: #field_type = #value; }
        } else {
            let value = gen_map_get_required(index, field_type, quote! { map });
            quote! { let #field_name: #field_type = #value; }
        };

        field_extractions.push(extraction);
        field_names.push(field_name);
    }

    Ok(quote! {
        let case = cbor.into_case();
        let dcbor::CBORCase::Map(map) = case else {
            return Err(dcbor::Error::WrongType);
        };

        #(#field_extractions)*

        Ok(Self {
            #(#field_names),*
        })
    })
}

fn generate_newtype_struct_impls(field: &syn::Field) -> syn::Result<(TokenStream2, TokenStream2)> {
    let field_type = &field.ty;

    if get_field_index(&field.attrs).is_some() {
        return Err(syn::Error::new(
            field.span(),
            "newtype structs cannot have #[n(x)] attribute; use a named struct instead",
        ));
    }

    let into_body = gen_to_cbor(field_type, quote! { value.0 });
    let from_value = gen_from_cbor(field_type, quote! { cbor });
    let try_from_body = quote! { Ok(Self(#from_value)) };

    Ok((into_body, try_from_body))
}

//
// enum
//

fn generate_enum_into_cbor(
    enum_name: &syn::Ident,
    variants: &syn::punctuated::Punctuated<syn::Variant, syn::token::Comma>,
) -> syn::Result<TokenStream2> {
    let mut variant_arms = Vec::new();

    for variant in variants {
        let variant_name = &variant.ident;
        let variant_index = get_field_index(&variant.attrs)
            .ok_or_else(|| syn::Error::new(variant.span(), "missing #[n(x)] attribute"))?;

        let arm = match &variant.fields {
            Fields::Unit => {
                quote! {
                    #enum_name::#variant_name => {
                        dcbor::CBOR::from(vec![dcbor::CBOR::from(#variant_index)])
                    }
                }
            }
            Fields::Unnamed(fields) => {
                generate_tuple_variant_into_cbor(enum_name, variant_name, variant_index, fields)?
            }
            Fields::Named(fields) => {
                generate_struct_variant_into_cbor(enum_name, variant_name, variant_index, fields)?
            }
        };

        variant_arms.push(arm);
    }

    Ok(quote! {
        match value {
            #(#variant_arms)*
        }
    })
}

fn generate_tuple_variant_into_cbor(
    enum_name: &syn::Ident,
    variant_name: &syn::Ident,
    variant_index: u64,
    fields: &syn::FieldsUnnamed,
) -> syn::Result<TokenStream2> {
    if fields.unnamed.len() != 1 {
        return Err(syn::Error::new(
            fields.span(),
            "tuple variants must have exactly one field",
        ));
    }

    let field = fields.unnamed.first().unwrap();
    let field_type = &field.ty;

    if get_field_index(&field.attrs).is_some() {
        return Err(syn::Error::new(
            field.span(),
            "tuple variant fields cannot have #[n(x)] attribute; use a struct variant instead",
        ));
    }

    Ok(quote! {
        #enum_name::#variant_name(inner) => {
            const _: fn() = || {
                fn assert_cbor_marker<T: crate::CborMarker>() {}
                assert_cbor_marker::<#field_type>();
            };
            dcbor::CBOR::from(vec![
                dcbor::CBOR::from(#variant_index),
                dcbor::CBOR::from(inner),
            ])
        }
    })
}

fn generate_struct_variant_into_cbor(
    enum_name: &syn::Ident,
    variant_name: &syn::Ident,
    variant_index: u64,
    fields: &syn::FieldsNamed,
) -> syn::Result<TokenStream2> {
    let mut field_names = Vec::new();
    let mut field_insertions = Vec::new();

    for field in &fields.named {
        let field_name = field.ident.as_ref().unwrap();
        let field_type = &field.ty;
        let field_index = get_field_index(&field.attrs)
            .ok_or_else(|| syn::Error::new(field.span(), "missing #[n(x)] attribute"))?;

        field_names.push(field_name);

        let cbor_value = gen_to_cbor(field_type, quote! { #field_name });
        field_insertions.push(quote! {
            inner_map.insert(dcbor::CBOR::from(#field_index), #cbor_value);
        });
    }

    Ok(quote! {
        #enum_name::#variant_name { #(#field_names),* } => {
            let mut inner_map = dcbor::Map::new();
            #(#field_insertions)*

            dcbor::CBOR::from(vec![
                dcbor::CBOR::from(#variant_index),
                dcbor::CBOR::from(inner_map),
            ])
        }
    })
}

fn generate_enum_try_from_cbor(
    variants: &syn::punctuated::Punctuated<syn::Variant, syn::token::Comma>,
) -> syn::Result<TokenStream2> {
    let mut variant_arms = Vec::new();

    for variant in variants {
        let variant_name = &variant.ident;
        let variant_index = get_field_index(&variant.attrs)
            .ok_or_else(|| syn::Error::new(variant.span(), "missing #[n(x)] attribute"))?;

        let arm = match &variant.fields {
            Fields::Unit => {
                quote! { #variant_index => Ok(Self::#variant_name), }
            }
            Fields::Unnamed(fields) => {
                generate_tuple_variant_try_from_cbor(variant_name, variant_index, fields)?
            }
            Fields::Named(fields) => {
                generate_struct_variant_try_from_cbor(variant_name, variant_index, fields)?
            }
        };

        variant_arms.push(arm);
    }

    Ok(quote! {
        let case = cbor.into_case();
        let dcbor::CBORCase::Array(arr) = case else {
            return Err(dcbor::Error::WrongType);
        };

        let variant_index: u64 = <u64 as TryFrom<dcbor::CBOR>>::try_from(
            arr.get(0).ok_or(dcbor::Error::WrongType)?.clone()
        )?;

        match variant_index {
            #(#variant_arms)*
            _ => Err(dcbor::Error::WrongType),
        }
    })
}

fn generate_tuple_variant_try_from_cbor(
    variant_name: &syn::Ident,
    variant_index: u64,
    fields: &syn::FieldsUnnamed,
) -> syn::Result<TokenStream2> {
    if fields.unnamed.len() != 1 {
        return Err(syn::Error::new(
            fields.span(),
            "tuple variants must have exactly one field",
        ));
    }

    let field = fields.unnamed.first().unwrap();
    let field_type = &field.ty;

    if get_field_index(&field.attrs).is_some() {
        return Err(syn::Error::new(
            field.span(),
            "tuple variant fields cannot have #[n(x)] attribute; use a struct variant instead",
        ));
    }

    Ok(quote! {
        #variant_index => {
            let variant_data = arr.get(1).ok_or(dcbor::Error::WrongType)?;
            let inner: #field_type = variant_data.clone().try_into()?;
            Ok(Self::#variant_name(inner))
        }
    })
}

fn generate_struct_variant_try_from_cbor(
    variant_name: &syn::Ident,
    variant_index: u64,
    fields: &syn::FieldsNamed,
) -> syn::Result<TokenStream2> {
    let mut field_extractions = Vec::new();
    let mut field_names = Vec::new();

    for field in &fields.named {
        let field_name = field.ident.as_ref().unwrap();
        let field_type = &field.ty;
        let field_index = get_field_index(&field.attrs)
            .ok_or_else(|| syn::Error::new(field.span(), "missing #[n(x)] attribute"))?;

        let extraction = if let Some(inner) = get_option_inner(field_type) {
            let value = gen_map_get_optional(field_index, &inner, quote! { inner_map });
            quote! { let #field_name: #field_type = #value; }
        } else {
            let value = gen_map_get_required(field_index, field_type, quote! { inner_map });
            quote! { let #field_name: #field_type = #value; }
        };

        field_extractions.push(extraction);
        field_names.push(field_name);
    }

    Ok(quote! {
        #variant_index => {
            let variant_data = arr.get(1).ok_or(dcbor::Error::WrongType)?;
            let inner_case = variant_data.clone().into_case();
            let dcbor::CBORCase::Map(inner_map) = inner_case else {
                return Err(dcbor::Error::WrongType);
            };

            #(#field_extractions)*

            Ok(Self::#variant_name {
                #(#field_names),*
            })
        }
    })
}

//
// helpers
//

fn gen_to_cbor(field_type: &Type, value: TokenStream2) -> TokenStream2 {
    if is_vec_u8(field_type) || is_u8_array(field_type) {
        quote! { dcbor::CBOR::to_byte_string(#value) }
    } else {
        quote! { dcbor::CBOR::from(#value) }
    }
}

fn gen_from_cbor(field_type: &Type, cbor: TokenStream2) -> TokenStream2 {
    if is_vec_u8(field_type) {
        quote! { #cbor.try_into_byte_string()?.to_vec() }
    } else if is_u8_array(field_type) {
        gen_byte_array_from_cbor(field_type, cbor)
    } else {
        quote! { #cbor.try_into()? }
    }
}

fn gen_byte_array_from_cbor(field_type: &Type, cbor: TokenStream2) -> TokenStream2 {
    quote! {{
        let bytes = #cbor.try_into_byte_string()?;
        <#field_type>::try_from(bytes.as_ref())
            .map_err(|_| dcbor::Error::OutOfRange)?
    }}
}

fn gen_map_insert(index: u64, field_type: &Type, value: TokenStream2) -> TokenStream2 {
    let cbor_value = gen_to_cbor(field_type, value);
    quote! {
        map.insert(dcbor::CBOR::from(#index), #cbor_value);
    }
}

fn gen_map_get_required(index: u64, field_type: &Type, map: TokenStream2) -> TokenStream2 {
    let cbor_expr = quote! {
        #map.get::<u64, dcbor::CBOR>(#index)
            .ok_or(dcbor::Error::MissingMapKey)?
    };
    gen_from_cbor(field_type, cbor_expr)
}

fn gen_map_get_optional(index: u64, inner_type: &Type, map: TokenStream2) -> TokenStream2 {
    let value_expr = if is_vec_u8(inner_type) {
        quote! { field_cbor.try_into_byte_string()?.to_vec() }
    } else if is_u8_array(inner_type) {
        gen_byte_array_from_cbor(inner_type, quote! { field_cbor })
    } else {
        quote! { field_cbor.try_into()? }
    };

    quote! {
        match #map.get::<u64, dcbor::CBOR>(#index) {
            Some(field_cbor) => Some(#value_expr),
            None => None,
        }
    }
}

fn get_field_index(attrs: &[Attribute]) -> Option<u64> {
    for attr in attrs {
        if attr.path().is_ident("n") {
            if let Meta::List(meta_list) = &attr.meta {
                let tokens = meta_list.tokens.clone();
                if let Ok(Lit::Int(lit_int)) = syn::parse2::<Lit>(tokens) {
                    return lit_int.base10_parse().ok();
                }
            }
        }
    }
    None
}

fn get_option_inner(ty: &Type) -> Option<Type> {
    let Type::Path(p) = ty else { return None };
    let seg = p.path.segments.last().filter(|s| s.ident == "Option")?;
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return None;
    };
    let syn::GenericArgument::Type(inner) = args.args.first()? else {
        return None;
    };
    Some(inner.clone())
}

fn is_vec_u8(ty: &Type) -> bool {
    let Type::Path(p) = ty else { return false };
    let Some(seg) = p.path.segments.last().filter(|s| s.ident == "Vec") else {
        return false;
    };
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return false;
    };
    let Some(syn::GenericArgument::Type(Type::Path(inner))) = args.args.first() else {
        return false;
    };
    inner
        .path
        .segments
        .last()
        .map(|s| s.ident == "u8")
        .unwrap_or(false)
}

fn is_u8_array(ty: &Type) -> bool {
    let Type::Array(array) = ty else { return false };
    let Type::Path(p) = &*array.elem else {
        return false;
    };
    p.path
        .segments
        .last()
        .map(|s| s.ident == "u8")
        .unwrap_or(false)
}
