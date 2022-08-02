use syn::{self, punctuated::Punctuated};

use generator::Result;
use spanned::Spanned;
use proc_macro::Span;

#[derive(Debug, Copy, Clone)]
pub enum MetaItem<'a> {
    Path(&'a syn::Path),
    Literal(&'a syn::Lit),
    KeyValue(&'a syn::Path, &'a syn::Lit),
    List(MetaItemList<'a>)
}

#[derive(Debug, Copy, Clone)]
pub struct MetaItemList<'a> {
    pub path: &'a syn::Path,
    pub iter: &'a Punctuated<syn::NestedMeta, syn::token::Comma>
}

impl<'a> MetaItemList<'a> {
    pub fn iter(&self) -> impl Iterator<Item = MetaItem<'a>> {
        self.iter.iter().map(MetaItem::from)
    }
}

impl<'a> Spanned for MetaItemList<'a> {
    fn span(&self) -> Span {
        self.iter.span()
    }
}

impl<'a> From<&'a syn::Meta> for MetaItem<'a> {
    fn from(meta: &syn::Meta) -> MetaItem {
        match meta {
            syn::Meta::Path(p) => MetaItem::Path(p),
            syn::Meta::NameValue(nv) => MetaItem::KeyValue(&nv.path, &nv.lit),
            syn::Meta::List(list) => {
                MetaItem::List(MetaItemList { path: &list.path, iter: &list.nested })
            }
        }
    }
}

impl<'a> From<&'a syn::NestedMeta> for MetaItem<'a> {
    fn from(nested: &syn::NestedMeta) -> MetaItem {
        match nested {
            syn::NestedMeta::Meta(meta) => MetaItem::from(meta),
            syn::NestedMeta::Lit(lit) => MetaItem::Literal(lit),
        }
    }
}

impl<'a> MetaItem<'a> {
    pub fn path(&self) -> Option<&syn::Path> {
        use MetaItem::*;

        match self {
            Path(p) | KeyValue(p, _) | List(MetaItemList { path: p, .. }) => {
                Some(p)
            }
            _ => None
        }
    }

    pub fn name(&self) -> Option<&syn::Ident> {
        let path = self.path()?;
        path.segments.last().map(|l| &l.ident)
    }

    pub fn description(&self) -> &'static str {
        match self {
            MetaItem::Path(..) => "path",
            MetaItem::Literal(syn::Lit::Str(..)) => "string literal",
            MetaItem::Literal(syn::Lit::ByteStr(..)) => "byte string literal",
            MetaItem::Literal(syn::Lit::Byte(..)) => "byte literal",
            MetaItem::Literal(syn::Lit::Char(..)) => "character literal",
            MetaItem::Literal(syn::Lit::Int(..)) => "integer literal",
            MetaItem::Literal(syn::Lit::Float(..)) => "float literal",
            MetaItem::Literal(syn::Lit::Bool(..)) => "boolean literal",
            MetaItem::Literal(syn::Lit::Verbatim(..)) => "literal",
            MetaItem::KeyValue(..) => "key/value pair",
            MetaItem::List(..) => "list",
        }
    }

    pub fn is_bare(&self) -> bool {
        match self {
            MetaItem::Path(..) | MetaItem::Literal(..) => true,
            MetaItem::KeyValue(..) | MetaItem::List(..) => false,
        }
    }

    pub fn lit(&self) -> Result<&syn::Lit> {
        match self {
            MetaItem::Literal(lit) | MetaItem::KeyValue(_, lit) => Ok(lit),
            _ => Err(self.span().error("expected literal or key/value pair"))
        }
    }

    pub fn value_span(&self) -> Span {
        match self {
            MetaItem::KeyValue(_, lit) => lit.span(),
            _ => self.span(),
        }
    }
}

impl<'a> Spanned for MetaItem<'a> {
    fn span(&self) -> Span {
        match self {
            MetaItem::Path(p) => p.span(),
            MetaItem::Literal(l) => l.span(),
            MetaItem::KeyValue(i, l) => {
                i.span().join(l.span()).unwrap_or(Span::call_site())
            }
            MetaItem::List(l) => l.span(),
        }
    }
}
