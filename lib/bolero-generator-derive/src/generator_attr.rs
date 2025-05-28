use proc_macro2::TokenStream as TokenStream2;
use quote::{quote, quote_spanned, ToTokens};
use syn::{parse::Error, spanned::Spanned, Attribute, LitStr, Meta, MetaList};

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
            tokens.extend(quote!(#krate::produce()));
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
            if attr.path().is_ident("generator") {
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
        match &attr.meta {
            Meta::Path(_) => Ok(Self {
                krate: krate.clone(),
                generator: None,
            }),
            Meta::List(meta) => {
                if let Some(generator) = parse_code_hack(meta)? {
                    // #[generator(_code = "...")]
                    return Ok(Self {
                        krate: krate.clone(),
                        generator: Some(generator.to_token_stream()),
                    });
                }

                // #[generator(...)]
                Ok(Self {
                    krate: krate.clone(),
                    generator: Some(meta.tokens.clone()),
                })
            }
            Meta::NameValue(meta) => Ok(Self {
                krate: krate.clone(),
                generator: Some(meta.value.to_token_stream()),
            }),
        }
    }
}

fn parse_code_hack(meta: &MetaList) -> Result<Option<TokenStream2>, Error> {
    let mut nested_len = 0;
    let mut code_hack = None;
    if meta
        .parse_nested_meta(|meta| {
            nested_len += 1;

            if !meta.path.is_ident("_code") {
                return Ok(());
            }

            let lit: LitStr = meta.value()?.parse()?;
            code_hack = Some(lit.parse()?);
            Ok(())
        })
        .is_err()
    {
        // last effort to make it work
        return Ok(None);
    }

    if nested_len != 1 {
        return Err(Error::new(
            if nested_len == 0 {
                meta.span()
            } else {
                meta.tokens.span()
            },
            "Expected single value in #[generator(...)]",
        ));
    }

    Ok(code_hack)
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
