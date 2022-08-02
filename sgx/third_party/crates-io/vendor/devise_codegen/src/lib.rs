#![feature(proc_macro_diagnostic, proc_macro_span)]
#![recursion_limit="256"]

extern crate proc_macro;
#[macro_use] extern crate quote;
extern crate devise_core;

use proc_macro::TokenStream;
use devise_core::*;

struct Naked(bool);

impl FromMeta for Naked {
    fn from_meta(meta: MetaItem) -> Result<Naked> {
        if let MetaItem::List(list) = meta {
            if list.iter.len() != 1 {
                return Err(list.span().error("expected exactly one parameter"));
            }

            let item = list.iter().next().unwrap();
            if let MetaItem::Path(path) = item {
                if path.is_ident("naked") {
                    return Ok(Naked(true));
                }
            }

            Err(item.span().error("expected `naked`"))
        } else {
            Err(meta.span().error("malformed attribute: expected list"))
        }
    }
}

#[proc_macro_derive(FromMeta, attributes(meta))]
pub fn derive_from_meta(input: TokenStream) -> TokenStream {
    DeriveGenerator::build_for(input, quote!(impl ::devise::FromMeta))
        .data_support(DataSupport::NamedStruct)
        .function(|_, inner| quote! {
            fn from_meta(
                __meta: ::devise::MetaItem
            ) -> ::devise::Result<Self> {
                #inner
            }
        })
        .validate_fields(|_, fields| {
            for f in fields.iter() {
                Naked::from_attrs("meta", &f.attrs).unwrap_or(Ok(Naked(false)))?;
            }

            Ok(())
        })
        .map_struct(|_, data| {
            let naked = |field: &Field| -> bool {
                Naked::from_attrs("meta", &field.attrs)
                    .unwrap_or(Ok(Naked(false)))
                    .expect("checked in `validate_fields`")
                    .0
            };

            let constructors = data.fields().iter().map(|f| {
                let (ident, span) = (f.ident.as_ref().unwrap(), f.span().into());
                quote_spanned!(span => #[allow(unused_assignments)] let mut #ident = None;)
            });

            let naked_matchers = data.fields().iter().filter(naked).map(|f| {
                let (ident, span) = (f.ident.as_ref().unwrap(), f.span().into());
                let (name, ty) = (ident.to_string(), &f.ty);

                quote_spanned! { span =>
                    match __list.next() {
                        Some(__i) if __i.is_bare() => {
                            #ident = Some(<#ty>::from_meta(__i)?)
                        },
                        Some(__i) => return Err(__i.span().error(
                            "unexpected keyed parameter: expected literal or identifier")),
                        None => return Err(__span.error(
                            format!("missing expected parameter: `{}`", #name))),
                    };
                }
            });

            let named_matchers = data.fields().iter().filter(|f| !naked(f)).map(|f| {
                let (ident, span) = (f.ident.as_ref().unwrap(), f.span().into());
                let (name, ty) = (ident.to_string(), &f.ty);

                quote_spanned! { span =>
                    if __name == #name {
                        if #ident.is_some() {
                            return Err(__span.error(
                                format!("duplicate attribute parameter: {}", #name)));
                        }

                        #ident = Some(<#ty>::from_meta(__meta)?);
                        continue;
                    }
                }
            });

            let builders = data.fields().iter().map(|f| {
                let (ident, span) = (f.ident.as_ref().unwrap(), f.span().into());
                let name = ident.to_string();

                quote_spanned! { span =>
                    #ident: #ident.or_else(::devise::FromMeta::default)
                    .ok_or_else(|| __span.error(
                        format!("missing required attribute parameter: `{}`", #name)))?,
                }
            });

            quote! {
                use ::devise::Spanned;

                // First, check that the attribute is a list: name(list, ..) and
                // generate __list: iterator over the items in the attribute.
                let __span = __meta.span();
                let mut __list = match __meta {
                    ::devise::MetaItem::List(__l) => __l.iter(),
                    _ => return Err(__span.error("malformed attribute")
                                    .help("expected syntax: #[attr(key = value, ..)]"))
                };

                // Set up the constructors for all the variables.
                #(#constructors)*

                // Then, parse all of the naked meta items.
                #(#naked_matchers)*

                // Parse the rest as non-naked meta items.
                for __meta in __list {
                    let __span = __meta.span();
                    let __name = match __meta.name() {
                        Some(__ident) => __ident,
                        None => return Err(__span.error("expected key/value pair"))
                    };

                    #(#named_matchers)*

                    let __msg = format!("unexpected attribute parameter: `{}`", __name);
                    return Err(__span.error(__msg));
                }

                // Finally, build up the structure.
                Ok(Self { #(#builders)* })
            }
        })
        .to_tokens()
}
