use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    parse_macro_input, spanned::Spanned, Attribute, Data, DeriveInput, Fields, Lit, Meta, Type,
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

/// Derive macro that generates `Into<dcbor::CBOR>` and `TryFrom<dcbor::CBOR>` implementations.
///
/// Uses integer keys for struct fields and enum variants based on `#[n(x)]` attributes.
///
/// # Supported types:
/// - Structs with named fields
/// - Enums tuple or struct variants:
///   - `Variant(Type)`
///   - `Variant { field: Type }`
///
/// # Example
/// ```ignore
/// #[derive(Cbor)]
/// pub struct MyStruct {
///     #[n(0)]
///     pub field1: String,
///     #[n(1)]
///     pub field2: u32,
/// }
///
/// #[derive(Cbor)]
/// pub enum MyEnum {
///     #[n(0)]
///     Tuple(#[n(0)] MyStruct),
///     #[n(1)]
///     Struct {
///         #[n(0)]
///         value: u8,
///     },
/// }
/// ```
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
        Data::Struct(data_struct) => match &data_struct.fields {
            Fields::Named(fields) => {
                let into_body = generate_struct_into_cbor(&fields.named)?;
                let try_from_body = generate_struct_try_from_cbor(&fields.named)?;
                (into_body, try_from_body)
            }
            Fields::Unnamed(fields) => {
                if fields.unnamed.len() != 1 {
                    return Err(syn::Error::new(
                        fields.span(),
                        "only single-field tuple structs (newtypes) are supported",
                    ));
                }
                let field_type = &fields.unnamed.first().unwrap().ty;
                
                // Newtype struct: just wrap/unwrap the inner value
                let into_body = if is_vec_u8(field_type) || is_u8_array(field_type) {
                    quote! {
                        dcbor::CBOR::to_byte_string(value.0)
                    }
                } else {
                    quote! {
                        dcbor::CBOR::from(value.0)
                    }
                };
                
                let try_from_body = if is_vec_u8(field_type) {
                    quote! {
                        Ok(Self(cbor.try_into_byte_string()?.to_vec()))
                    }
                } else if is_u8_array(field_type) {
                    quote! {
                        let bytes = cbor.try_into_byte_string()?;
                        Ok(Self(<#field_type>::try_from(bytes.as_ref())
                            .map_err(|_| dcbor::Error::OutOfRange)?))
                    }
                } else {
                    quote! {
                        Ok(Self(cbor.try_into()?))
                    }
                };
                
                (into_body, try_from_body)
            }
            Fields::Unit => {
                return Err(syn::Error::new(name.span(), "unit structs not supported"));
            }
        },
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
    })
}

/// Extract the integer index from `#[n(x)]` attribute
fn get_field_index(attrs: &[Attribute]) -> Option<u64> {
    for attr in attrs {
        if attr.path().is_ident("n") {
            if let Meta::List(meta_list) = &attr.meta {
                let tokens = meta_list.tokens.clone();
                if let Ok(lit) = syn::parse2::<Lit>(tokens) {
                    if let Lit::Int(lit_int) = lit {
                        return lit_int.base10_parse().ok();
                    }
                }
            }
        }
    }
    None
}

/// Generate the Into<CBOR> implementation body for structs
fn generate_struct_into_cbor(
    fields: &syn::punctuated::Punctuated<syn::Field, syn::token::Comma>,
) -> syn::Result<TokenStream2> {
    let mut field_insertions = Vec::new();

    for field in fields {
        let field_name = field.ident.as_ref().unwrap();
        let field_type = &field.ty;
        let index = get_field_index(&field.attrs)
            .ok_or_else(|| syn::Error::new(field.span(), "missing #[n(x)] attribute"))?;

        // Handle Option<T>
        if is_option_type(field_type) {
            let inner_type = get_option_inner_type(field_type);
            if let Some(inner) = inner_type {
                if is_vec_u8(&inner) || is_u8_array(&inner) {
                    field_insertions.push(quote! {
                        if let Some(val) = value.#field_name {
                            map.insert(dcbor::CBOR::from(#index), dcbor::CBOR::to_byte_string(val));
                        }
                    });
                } else {
                    field_insertions.push(quote! {
                        if let Some(val) = value.#field_name {
                            map.insert(dcbor::CBOR::from(#index), dcbor::CBOR::from(val));
                        }
                    });
                }
            } else {
                field_insertions.push(quote! {
                    if let Some(val) = value.#field_name {
                        map.insert(dcbor::CBOR::from(#index), dcbor::CBOR::from(val));
                    }
                });
            }
        } else if is_vec_u8(field_type) || is_u8_array(field_type) {
            // Use byte_string for Vec<u8> and [u8; N]
            field_insertions.push(quote! {
                map.insert(dcbor::CBOR::from(#index), dcbor::CBOR::to_byte_string(value.#field_name));
            });
        } else {
            field_insertions.push(quote! {
                map.insert(dcbor::CBOR::from(#index), dcbor::CBOR::from(value.#field_name));
            });
        }
    }

    Ok(quote! {
        let mut map = dcbor::Map::new();
        #(#field_insertions)*
        dcbor::CBOR::from(map)
    })
}

/// Get the inner type of Option<T>
fn get_option_inner_type(ty: &Type) -> Option<Type> {
    if let Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            if segment.ident == "Option" {
                if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                    if args.args.len() == 1 {
                        if let syn::GenericArgument::Type(inner_type) = &args.args[0] {
                            return Some(inner_type.clone());
                        }
                    }
                }
            }
        }
    }
    None
}

/// Generate the TryFrom<CBOR> implementation body for structs
fn generate_struct_try_from_cbor(
    fields: &syn::punctuated::Punctuated<syn::Field, syn::token::Comma>,
) -> syn::Result<TokenStream2> {
    let mut field_extractions = Vec::new();
    let mut field_names = Vec::new();

    for field in fields {
        let field_name = field.ident.as_ref().unwrap();
        let field_type = &field.ty;
        let index = get_field_index(&field.attrs)
            .ok_or_else(|| syn::Error::new(field.span(), "missing #[n(x)] attribute"))?;

        // Check if the type is Option<T>
        if is_option_type(field_type) {
            let inner_type = get_option_inner_type(field_type);
            if let Some(inner) = inner_type {
                if is_vec_u8(&inner) {
                    field_extractions.push(quote! {
                        let #field_name: #field_type = match map.get::<u64, dcbor::CBOR>(#index) {
                            Some(field_cbor) => Some(field_cbor.try_into_byte_string()?.to_vec()),
                            None => None,
                        };
                    });
                } else if is_u8_array(&inner) {
                    field_extractions.push(quote! {
                        let #field_name: #field_type = match map.get::<u64, dcbor::CBOR>(#index) {
                            Some(field_cbor) => {
                                let bytes = field_cbor.try_into_byte_string()?;
                                Some(<#inner>::try_from(bytes.as_ref())
                                    .map_err(|_| dcbor::Error::OutOfRange)?)
                            },
                            None => None,
                        };
                    });
                } else {
                    field_extractions.push(quote! {
                        let #field_name: #field_type = match map.get::<u64, dcbor::CBOR>(#index) {
                            Some(field_cbor) => Some(<#inner as TryFrom<dcbor::CBOR>>::try_from(field_cbor)
                                .map_err(|_| dcbor::Error::WrongType)?),
                            None => None,
                        };
                    });
                }
            } else {
                field_extractions.push(quote! {
                    let #field_name: #field_type = match map.get::<u64, dcbor::CBOR>(#index) {
                        Some(field_cbor) => Some(field_cbor.try_into()
                            .map_err(|_| dcbor::Error::WrongType)?),
                        None => None,
                    };
                });
            }
        } else if is_vec_u8(field_type) {
            field_extractions.push(quote! {
                let #field_name: #field_type = map
                    .get::<u64, dcbor::CBOR>(#index)
                    .ok_or(dcbor::Error::MissingMapKey)?
                    .try_into_byte_string()?
                    .to_vec();
            });
        } else if is_u8_array(field_type) {
            field_extractions.push(quote! {
                let #field_name: #field_type = {
                    let bytes = map
                        .get::<u64, dcbor::CBOR>(#index)
                        .ok_or(dcbor::Error::MissingMapKey)?
                        .try_into_byte_string()?;
                    <#field_type>::try_from(bytes.as_ref())
                        .map_err(|_| dcbor::Error::OutOfRange)?
                };
            });
        } else {
            // Use explicit TryFrom to avoid Infallible error conversion issues
            field_extractions.push(quote! {
                let #field_name: #field_type = <#field_type as TryFrom<dcbor::CBOR>>::try_from(
                    map
                        .get::<u64, dcbor::CBOR>(#index)
                        .ok_or(dcbor::Error::MissingMapKey)?
                ).map_err(|_| dcbor::Error::WrongType)?;
            });
        }

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

/// Check if a type is Option<T>
fn is_option_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            return segment.ident == "Option";
        }
    }
    false
}

/// Check if a type is Vec<u8>
fn is_vec_u8(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            if segment.ident == "Vec" {
                if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                    if args.args.len() == 1 {
                        if let syn::GenericArgument::Type(Type::Path(inner)) = &args.args[0] {
                            if let Some(inner_seg) = inner.path.segments.last() {
                                return inner_seg.ident == "u8";
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

/// Check if a type is [u8; N]
fn is_u8_array(ty: &Type) -> bool {
    if let Type::Array(array) = ty {
        if let Type::Path(elem_path) = &*array.elem {
            if let Some(segment) = elem_path.path.segments.last() {
                return segment.ident == "u8";
            }
        }
    }
    false
}

/// Generate the Into<CBOR> implementation body for enums
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
                // Unit variant: encode as [index]
                quote! {
                    #enum_name::#variant_name => {
                        dcbor::CBOR::from(vec![dcbor::CBOR::from(#variant_index)])
                    }
                }
            }
            Fields::Unnamed(fields) => {
                if fields.unnamed.len() != 1 {
                    return Err(syn::Error::new(
                        fields.span(),
                        "tuple variants must have exactly one field",
                    ));
                }
                // Tuple variant with single field: encode as [index, field_value]
                quote! {
                    #enum_name::#variant_name(inner) => {
                        dcbor::CBOR::from(vec![
                            dcbor::CBOR::from(#variant_index),
                            dcbor::CBOR::from(inner),
                        ])
                    }
                }
            }
            Fields::Named(fields) => {
                // Struct variant: encode as [index, {field_indices...}]
                let mut field_names = Vec::new();
                let mut field_insertions = Vec::new();

                for field in &fields.named {
                    let field_name = field.ident.as_ref().unwrap();
                    let field_type = &field.ty;
                    let field_index = get_field_index(&field.attrs).ok_or_else(|| {
                        syn::Error::new(field.span(), "missing #[n(x)] attribute")
                    })?;

                    field_names.push(field_name);

                    // Use byte_string for Vec<u8> and [u8; N]
                    if is_vec_u8(field_type) || is_u8_array(field_type) {
                        field_insertions.push(quote! {
                            inner_map.insert(dcbor::CBOR::from(#field_index), dcbor::CBOR::to_byte_string(#field_name));
                        });
                    } else {
                        field_insertions.push(quote! {
                            inner_map.insert(dcbor::CBOR::from(#field_index), dcbor::CBOR::from(#field_name));
                        });
                    }
                }

                quote! {
                    #enum_name::#variant_name { #(#field_names),* } => {
                        let mut inner_map = dcbor::Map::new();
                        #(#field_insertions)*

                        dcbor::CBOR::from(vec![
                            dcbor::CBOR::from(#variant_index),
                            dcbor::CBOR::from(inner_map),
                        ])
                    }
                }
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

/// Generate the TryFrom<CBOR> implementation body for enums
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
                quote! {
                    #variant_index => Ok(Self::#variant_name),
                }
            }
            Fields::Unnamed(fields) => {
                if fields.unnamed.len() != 1 {
                    return Err(syn::Error::new(
                        fields.span(),
                        "tuple variants must have exactly one field",
                    ));
                }
                let field_type = &fields.unnamed.first().unwrap().ty;

                quote! {
                    #variant_index => {
                        let variant_data = arr.get(1).ok_or(dcbor::Error::WrongType)?;
                        let inner: #field_type = <#field_type as TryFrom<dcbor::CBOR>>::try_from(variant_data.clone())
                            .map_err(|_| dcbor::Error::WrongType)?;
                        Ok(Self::#variant_name(inner))
                    }
                }
            }
            Fields::Named(named_fields) => {
                let mut field_extractions = Vec::new();
                let mut field_names = Vec::new();

                for field in &named_fields.named {
                    let field_name = field.ident.as_ref().unwrap();
                    let field_type = &field.ty;
                    let field_index = get_field_index(&field.attrs).ok_or_else(|| {
                        syn::Error::new(field.span(), "missing #[n(x)] attribute")
                    })?;

                    if is_option_type(field_type) {
                        let inner_type = get_option_inner_type(field_type);
                        if let Some(inner) = inner_type {
                            if is_vec_u8(&inner) {
                                field_extractions.push(quote! {
                                    let #field_name: #field_type = match inner_map.get::<u64, dcbor::CBOR>(#field_index) {
                                        Some(field_cbor) => Some(field_cbor.try_into_byte_string()?.to_vec()),
                                        None => None,
                                    };
                                });
                            } else if is_u8_array(&inner) {
                                field_extractions.push(quote! {
                                    let #field_name: #field_type = match inner_map.get::<u64, dcbor::CBOR>(#field_index) {
                                        Some(field_cbor) => {
                                            let bytes = field_cbor.try_into_byte_string()?;
                                            Some(<#inner>::try_from(bytes.as_ref())
                                                .map_err(|_| dcbor::Error::OutOfRange)?)
                                        },
                                        None => None,
                                    };
                                });
                            } else {
                                field_extractions.push(quote! {
                                    let #field_name: #field_type = match inner_map.get::<u64, dcbor::CBOR>(#field_index) {
                                        Some(field_cbor) => Some(<#inner as TryFrom<dcbor::CBOR>>::try_from(field_cbor)
                                            .map_err(|_| dcbor::Error::WrongType)?),
                                        None => None,
                                    };
                                });
                            }
                        } else {
                            field_extractions.push(quote! {
                                let #field_name: #field_type = match inner_map.get::<u64, dcbor::CBOR>(#field_index) {
                                    Some(field_cbor) => Some(field_cbor.try_into()
                                        .map_err(|_| dcbor::Error::WrongType)?),
                                    None => None,
                                };
                            });
                        }
                    } else if is_vec_u8(field_type) {
                        field_extractions.push(quote! {
                            let #field_name: #field_type = inner_map
                                .get::<u64, dcbor::CBOR>(#field_index)
                                .ok_or(dcbor::Error::MissingMapKey)?
                                .try_into_byte_string()?
                                .to_vec();
                        });
                    } else if is_u8_array(field_type) {
                        field_extractions.push(quote! {
                            let #field_name: #field_type = {
                                let bytes = inner_map
                                    .get::<u64, dcbor::CBOR>(#field_index)
                                    .ok_or(dcbor::Error::MissingMapKey)?
                                    .try_into_byte_string()?;
                                <#field_type>::try_from(bytes.as_ref())
                                    .map_err(|_| dcbor::Error::OutOfRange)?
                            };
                        });
                    } else {
                        // Use explicit TryFrom to avoid Infallible error conversion issues
                        field_extractions.push(quote! {
                            let #field_name: #field_type = <#field_type as TryFrom<dcbor::CBOR>>::try_from(
                                inner_map
                                    .get::<u64, dcbor::CBOR>(#field_index)
                                    .ok_or(dcbor::Error::MissingMapKey)?
                            ).map_err(|_| dcbor::Error::WrongType)?;
                        });
                    }

                    field_names.push(field_name);
                }

                quote! {
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
                }
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
            arr
                .get(0)
                .ok_or(dcbor::Error::WrongType)?
                .clone()
        ).map_err(|_| dcbor::Error::WrongType)?;

        match variant_index {
            #(#variant_arms)*
            _ => Err(dcbor::Error::WrongType),
        }
    })
}
