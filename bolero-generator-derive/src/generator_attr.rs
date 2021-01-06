use proc_macro2::TokenStream as TokenStream2;
use quote::{quote, quote_spanned, ToTokens};
use syn::{
    parse::Error, parse_quote, spanned::Spanned, Attribute, Expr, Lit, Meta, MetaList, NestedMeta,
    Type, WhereClause,
};

pub struct GeneratorAttr {
    pub generator: Option<TokenStream2>,
}

impl ToTokens for GeneratorAttr {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        if let Some(generator) = self.generator.as_ref() {
            tokens.extend(quote!(#generator));
        } else {
            tokens.extend(quote!(bolero_generator::gen()));
        }
    }
}

impl GeneratorAttr {
    pub fn value_generate(&self) -> GeneratorAttrValue {
        GeneratorAttrValue(self)
    }

    pub fn from_attrs<'a, I: Iterator<Item = &'a Attribute>>(attributes: I) -> Self {
        for attr in attributes {
            if attr.path.is_ident("generator") {
                return match Self::from_attr(attr) {
                    Ok(generator) => generator,
                    Err(err) => Self {
                        generator: Some(err.to_compile_error()),
                    },
                };
            }
        }

        Self { generator: None }
    }

    pub fn from_attr(attr: &Attribute) -> Result<Self, Error> {
        match attr.parse_meta() {
            Ok(Meta::Path(_)) => Ok(Self { generator: None }),
            Ok(Meta::List(meta)) => {
                if let Some(generator) = parse_code_hack(&meta)? {
                    // #[generator(_code = "...")]
                    return Ok(Self {
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
                    generator: Some(generator),
                })
            }
            Ok(Meta::NameValue(meta)) => Ok(Self {
                generator: Some(meta.lit.to_token_stream()),
            }),
            Err(error) => {
                // last effort to make it work
                if let Ok(expr) = attr.parse_args::<Expr>() {
                    return Ok(Self {
                        generator: Some(expr.to_token_stream()),
                    });
                }

                Err(error)
            }
        }
    }

    pub fn apply_constraint(&self, ty: &Type, where_clause: &mut WhereClause) {
        if self.generator.is_none() {
            let span = ty.span();
            let constraint = quote_spanned!(span=> : bolero_generator::TypeGenerator);
            where_clause.predicates.push(parse_quote!(#ty #constraint));
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
        let generator = self.0;
        let span = generator.span();
        tokens.extend(quote_spanned!(span=>
            bolero_generator::ValueGenerator::generate(&(#generator), __bolero_driver)?
        ))
    }
}
