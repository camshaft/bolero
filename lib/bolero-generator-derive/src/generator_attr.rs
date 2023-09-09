use proc_macro2::TokenStream as TokenStream2;
use quote::{quote, quote_spanned, ToTokens};
use syn::{parse::Error, spanned::Spanned, Attribute, Expr, Lit, Meta, MetaList, NestedMeta};

pub struct GeneratorAttr {
    krate: TokenStream2,
    pub generator: Option<TokenStream2>,
}

impl ToTokens for GeneratorAttr {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        if let Some(generator) = self.generator.as_ref() {
            tokens.extend(quote!(#generator));
        } else {
            let krate = &self.krate;
            tokens.extend(quote!(#krate::gen()));
        }
    }
}

impl GeneratorAttr {
    pub fn value_generate(&self) -> GeneratorAttrValue {
        GeneratorAttrValue(self)
    }

    pub fn from_attrs<'a, I: Iterator<Item = &'a Attribute>>(
        krate: &TokenStream2,
        attributes: I,
    ) -> Self {
        for attr in attributes {
            if attr.path.is_ident("generator") {
                return match Self::from_attr(krate, attr) {
                    Ok(generator) => generator,
                    Err(err) => Self {
                        krate: krate.clone(),
                        generator: Some(err.to_compile_error()),
                    },
                };
            }
        }

        Self {
            krate: krate.clone(),
            generator: None,
        }
    }

    pub fn from_attr(krate: &TokenStream2, attr: &Attribute) -> Result<Self, Error> {
        match attr.parse_meta() {
            Ok(Meta::Path(_)) => Ok(Self {
                krate: krate.clone(),
                generator: None,
            }),
            Ok(Meta::List(meta)) => {
                if let Some(generator) = parse_code_hack(&meta)? {
                    // #[generator(_code = "...")]
                    return Ok(Self {
                        krate: krate.clone(),
                        generator: Some(generator.to_token_stream()),
                    });
                }

                if meta.nested.len() != 1 {
                    return Err(Error::new(
                        if meta.nested.is_empty() {
                            meta.span()
                        } else {
                            meta.nested.span()
                        },
                        "Expected single value in #[generator(...)]",
                    ));
                }

                // #[generator(...)]
                let generator = meta
                    .nested
                    .first()
                    .expect("length already checked above")
                    .to_token_stream();
                Ok(Self {
                    krate: krate.clone(),
                    generator: Some(generator),
                })
            }
            Ok(Meta::NameValue(meta)) => Ok(Self {
                krate: krate.clone(),
                generator: Some(meta.lit.to_token_stream()),
            }),
            Err(error) => {
                // last effort to make it work
                if let Ok(expr) = attr.parse_args::<Expr>() {
                    return Ok(Self {
                        krate: krate.clone(),
                        generator: Some(expr.to_token_stream()),
                    });
                }

                Err(error)
            }
        }
    }
}

fn parse_code_hack(meta: &MetaList) -> Result<Option<TokenStream2>, Error> {
    for meta in meta.nested.iter() {
        if let NestedMeta::Meta(Meta::NameValue(meta)) = meta {
            if !meta.path.is_ident("_code") {
                continue;
            }
            if let Lit::Str(lit) = &meta.lit {
                return Ok(Some(lit.parse()?));
            }
        };
    }
    Ok(None)
}

pub struct GeneratorAttrValue<'a>(&'a GeneratorAttr);

impl ToTokens for GeneratorAttrValue<'_> {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        let krate = &self.0.krate;
        let generator = self.0;
        let span = generator.span();
        tokens.extend(quote_spanned!(span=>
            #krate::ValueGenerator::generate(&(#generator), __bolero_driver)?
        ))
    }
}
