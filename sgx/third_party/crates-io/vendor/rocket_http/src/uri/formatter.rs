use std::fmt::{self, Write};
use std::marker::PhantomData;

use smallvec::SmallVec;

use crate::uri::{UriPart, Path, Query, UriDisplay, Origin};

/// A struct used to format strings for [`UriDisplay`].
///
/// # Marker Generic: `Formatter<Path>` vs. `Formatter<Query>`
///
/// Like [`UriDisplay`], the [`UriPart`] parameter `P` in `Formatter<P>` must be
/// either [`Path`] or [`Query`] resulting in either `Formatter<Path>` or
/// `Formatter<Query>`. The `Path` version is used when formatting parameters
/// in the path part of the URI while the `Query` version is used when
/// formatting parameters in the query part of the URI. The
/// [`write_named_value()`] method is only available to `UriDisplay<Query>`.
///
/// [`UriPart`]: crate::uri::UriPart
/// [`Path`]: crate::uri::Path
/// [`Query`]: crate::uri::Query
///
/// # Overview
///
/// A mutable version of this struct is passed to [`UriDisplay::fmt()`]. This
/// struct properly formats series of values for use in URIs. In particular,
/// this struct applies the following transformations:
///
///   * When **mutliple values** are written, they are separated by `/` for
///     `Path` types and `&` for `Query` types.
///
/// Additionally, for `Formatter<Query>`:
///
///   * When a **named value** is written with [`write_named_value()`], the name
///     is written out, followed by a `=`, followed by the value.
///
///   * When **nested named values** are written, typically by passing a value
///     to [`write_named_value()`] whose implementation of `UriDisplay` also
///     calls `write_named_vlaue()`, the nested names are joined by a `.`,
///     written out followed by a `=`, followed by the value.
///
/// [`UriDisplay`]: crate::uri::UriDisplay
/// [`UriDisplay::fmt()`]: crate::uri::UriDisplay::fmt()
/// [`write_named_value()`]: crate::uri::Formatter::write_named_value()
///
/// # Usage
///
/// Usage is fairly straightforward:
///
///   * For every _named value_ you wish to emit, call [`write_named_value()`].
///   * For every _unnamed value_ you wish to emit, call [`write_value()`].
///   * To write a string directly, call [`write_raw()`].
///
/// The `write_named_value` method automatically prefixes the `name` to the
/// written value and, along with `write_value` and `write_raw`, handles nested
/// calls to `write_named_value` automatically, prefixing names when necessary.
/// Unlike the other methods, `write_raw` does _not_ prefix any nested names
/// every time it is called. Instead, it only prefixes the _first_ time it is
/// called, after a call to `write_named_value` or `write_value`, or after a
/// call to [`refresh()`].
///
/// [`refresh()`]: crate::uri::Formatter::refresh()
///
/// # Example
///
/// The following example uses all of the `write` methods in a varied order to
/// display the semantics of `Formatter<Query>`. Note that `UriDisplay` should
/// rarely be implemented manually, preferring to use the derive, and that this
/// implementation is purely demonstrative.
///
/// ```rust
/// # extern crate rocket;
/// use std::fmt;
///
/// use rocket::http::uri::{Formatter, UriDisplay, Query};
///
/// struct Outer {
///     value: Inner,
///     another: usize,
///     extra: usize
/// }
///
/// struct Inner {
///     value: usize,
///     extra: usize
/// }
///
/// impl UriDisplay<Query> for Outer {
///     fn fmt(&self, f: &mut Formatter<Query>) -> fmt::Result {
///         f.write_named_value("outer_field", &self.value)?;
///         f.write_named_value("another", &self.another)?;
///         f.write_raw("out")?;
///         f.write_raw("side")?;
///         f.write_value(&self.extra)
///     }
/// }
///
/// impl UriDisplay<Query> for Inner {
///     fn fmt(&self, f: &mut Formatter<Query>) -> fmt::Result {
///         f.write_named_value("inner_field", &self.value)?;
///         f.write_value(&self.extra)?;
///         f.write_raw("inside")
///     }
/// }
///
/// let inner = Inner { value: 0, extra: 1 };
/// let outer = Outer { value: inner, another: 2, extra: 3 };
/// let uri_string = format!("{}", &outer as &UriDisplay<Query>);
/// assert_eq!(uri_string, "outer_field.inner_field=0&\
///                         outer_field=1&\
///                         outer_field=inside&\
///                         another=2&\
///                         outside&\
///                         3");
/// ```
///
/// Note that you can also use the `write!` macro to write directly to the
/// formatter as long as the [`std::fmt::Write`] trait is in scope. Internally,
/// the `write!` macro calls [`write_raw()`], so care must be taken to ensure
/// that the written string is URI-safe.
///
/// ```rust
/// # #[macro_use] extern crate rocket;
/// use std::fmt::{self, Write};
///
/// use rocket::http::uri::{UriDisplay, Formatter, UriPart, Path, Query};
///
/// pub struct Complex(u8, u8);
///
/// impl<P: UriPart> UriDisplay<P> for Complex {
///     fn fmt(&self, f: &mut Formatter<P>) -> fmt::Result {
///         write!(f, "{}+{}", self.0, self.1)
///     }
/// }
///
/// let uri_string = format!("{}", &Complex(42, 231) as &UriDisplay<Path>);
/// assert_eq!(uri_string, "42+231");
///
/// #[derive(UriDisplayQuery)]
/// struct Message {
///     number: Complex,
/// }
///
/// let message = Message { number: Complex(42, 47) };
/// let uri_string = format!("{}", &message as &UriDisplay<Query>);
/// assert_eq!(uri_string, "number=42+47");
/// ```
///
/// [`write_value()`]: crate::uri::Formatter::write_value()
/// [`write_raw()`]: crate::uri::Formatter::write_raw()
pub struct Formatter<'i, P: UriPart> {
    prefixes: SmallVec<[&'static str; 3]>,
    inner: &'i mut (dyn Write + 'i),
    previous: bool,
    fresh: bool,
    _marker: PhantomData<P>,
}

impl<'i, P: UriPart> Formatter<'i, P> {
    #[inline(always)]
    pub(crate) fn new(inner: &'i mut (dyn Write + 'i)) -> Self {
        Formatter {
            inner,
            prefixes: SmallVec::new(),
            previous: false,
            fresh: true,
            _marker: PhantomData,
        }
    }

    #[inline(always)]
    fn refreshed<F: FnOnce(&mut Self) -> fmt::Result>(&mut self, f: F) -> fmt::Result {
        self.refresh();
        let result = f(self);
        self.refresh();
        result
    }

    /// Writes `string` to `self`.
    ///
    /// If `self` is _fresh_ (after a call to other `write_` methods or
    /// [`refresh()`]), prefixes any names and adds separators as necessary.
    ///
    /// This method is called by the `write!` macro.
    ///
    /// [`refresh()`]: Formatter::refresh()
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate rocket;
    /// use std::fmt;
    ///
    /// use rocket::http::uri::{Formatter, UriDisplay, UriPart, Path};
    ///
    /// struct Foo;
    ///
    /// impl<P: UriPart> UriDisplay<P> for Foo {
    ///     fn fmt(&self, f: &mut Formatter<P>) -> fmt::Result {
    ///         f.write_raw("f")?;
    ///         f.write_raw("o")?;
    ///         f.write_raw("o")
    ///     }
    /// }
    ///
    /// let foo = Foo;
    /// let uri_string = format!("{}", &foo as &UriDisplay<Path>);
    /// assert_eq!(uri_string, "foo");
    /// ```
    pub fn write_raw<S: AsRef<str>>(&mut self, string: S) -> fmt::Result {
        // This implementation is a bit of a lie to the type system. Instead of
        // implementing this twice, one for <Path> and again for <Query>, we do
        // this once here. This is okay since we know that this handles the
        // cases for both Path and Query, and doing it this way allows us to
        // keep the uri part generic _generic_ in other implementations that use
        // `write_raw`.
        if self.fresh && P::DELIMITER == '/' {
            if self.previous {
                self.inner.write_char(P::DELIMITER)?;
            }
        } else if self.fresh && P::DELIMITER == '&' {
            if self.previous {
                self.inner.write_char(P::DELIMITER)?;
            }

            if !self.prefixes.is_empty() {
                for (i, prefix) in self.prefixes.iter().enumerate() {
                    self.inner.write_str(prefix)?;
                    if i < self.prefixes.len() - 1 {
                        self.inner.write_str(".")?;
                    }
                }

                self.inner.write_str("=")?;
            }
        }

        self.fresh = false;
        self.previous = true;
        self.inner.write_str(string.as_ref())
    }

    /// Writes the unnamed value `value`. Any nested names are prefixed as
    /// necessary.
    ///
    /// Refreshes `self` before and after the value is written.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate rocket;
    /// use std::fmt;
    ///
    /// use rocket::http::uri::{Formatter, UriDisplay, UriPart, Path, Query};
    ///
    /// struct Foo(usize);
    ///
    /// impl<P: UriPart> UriDisplay<P> for Foo {
    ///     fn fmt(&self, f: &mut Formatter<P>) -> fmt::Result {
    ///         f.write_value(&self.0)
    ///     }
    /// }
    ///
    /// let foo = Foo(123);
    ///
    /// let uri_string = format!("{}", &foo as &UriDisplay<Path>);
    /// assert_eq!(uri_string, "123");
    ///
    /// let uri_string = format!("{}", &foo as &UriDisplay<Query>);
    /// assert_eq!(uri_string, "123");
    /// ```
    #[inline]
    pub fn write_value<T: UriDisplay<P>>(&mut self, value: T) -> fmt::Result {
        self.refreshed(|f| UriDisplay::fmt(&value, f))
    }

    /// Refreshes the formatter.
    ///
    /// After refreshing, [`write_raw()`] will prefix any nested names as well
    /// as insert a separator.
    ///
    /// [`write_raw()`]: Formatter::write_raw()
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[macro_use] extern crate rocket;
    /// use std::fmt;
    ///
    /// use rocket::http::uri::{Formatter, UriDisplay, Query, Path};
    ///
    /// struct Foo;
    ///
    /// impl UriDisplay<Query> for Foo {
    ///     fn fmt(&self, f: &mut Formatter<Query>) -> fmt::Result {
    ///         f.write_raw("a")?;
    ///         f.write_raw("raw")?;
    ///         f.refresh();
    ///         f.write_raw("format")
    ///     }
    /// }
    ///
    /// let uri_string = format!("{}", &Foo as &UriDisplay<Query>);
    /// assert_eq!(uri_string, "araw&format");
    ///
    ///// #[derive(UriDisplayQuery)]
    ///// struct Message {
    /////     inner: Foo,
    ///// }
    /////
    ///// let msg = Message { inner: Foo };
    ///// let uri_string = format!("{}", &msg as &UriDisplay);
    ///// assert_eq!(uri_string, "inner=araw&inner=format");
    ///
    /// impl UriDisplay<Path> for Foo {
    ///     fn fmt(&self, f: &mut Formatter<Path>) -> fmt::Result {
    ///         f.write_raw("a")?;
    ///         f.write_raw("raw")?;
    ///         f.refresh();
    ///         f.write_raw("format")
    ///     }
    /// }
    ///
    /// let uri_string = format!("{}", &Foo as &UriDisplay<Path>);
    /// assert_eq!(uri_string, "araw/format");
    /// ```
    #[inline(always)]
    pub fn refresh(&mut self) {
        self.fresh = true;
    }
}

impl Formatter<'_, Query> {
    fn with_prefix<F>(&mut self, prefix: &str, f: F) -> fmt::Result
        where F: FnOnce(&mut Self) -> fmt::Result
    {
        // The `prefix` string is pushed in a `StackVec` for use by recursive
        // (nested) calls to `write_raw`. The string is pushed here and then
        // popped here. `self.prefixes` is modified nowhere else, and no strings
        // leak from the the vector. As a result, it is impossible for a
        // `prefix` to be accessed incorrectly as:
        //
        //   * Rust _guarantees_ it exists for the lifetime of this method
        //   * it is only reachable while this method's stack is active because
        //     it is popped before this method returns
        //   * thus, at any point that it's reachable, it's valid
        //
        // Said succinctly: this `prefixes` stack shadows a subset of the
        // `with_prefix` stack precisely, making it reachable to other code.
        let prefix: &'static str = unsafe { std::mem::transmute(prefix) };

        self.prefixes.push(prefix);
        let result = f(self);
        self.prefixes.pop();

        result
    }

    /// Writes the named value `value` by prefixing `name` followed by `=` to
    /// the value. Any nested names are also prefixed as necessary.
    ///
    /// Refreshes `self` before the name is written and after the value is
    /// written.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate rocket;
    /// use std::fmt;
    ///
    /// use rocket::http::uri::{Formatter, UriDisplay, Query};
    ///
    /// struct Foo {
    ///     name: usize
    /// }
    ///
    /// // Note: This is identical to what #[derive(UriDisplayQuery)] would
    /// // generate! In practice, _always_ use the derive.
    /// impl UriDisplay<Query> for Foo {
    ///     fn fmt(&self, f: &mut Formatter<Query>) -> fmt::Result {
    ///         f.write_named_value("name", &self.name)
    ///     }
    /// }
    ///
    /// let foo = Foo { name: 123 };
    /// let uri_string = format!("{}", &foo as &UriDisplay<Query>);
    /// assert_eq!(uri_string, "name=123");
    /// ```
    #[inline]
    pub fn write_named_value<T: UriDisplay<Query>>(&mut self, name: &str, value: T) -> fmt::Result {
        self.refreshed(|f| f.with_prefix(name, |f| f.write_value(value)))
    }
}

impl<P: UriPart> fmt::Write for Formatter<'_, P> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_raw(s)
    }
}

// Used by code generation.
#[doc(hidden)]
pub enum UriArgumentsKind<A> {
    Static(&'static str),
    Dynamic(A)
}

// Used by code generation.
#[doc(hidden)]
pub enum UriQueryArgument<'a> {
    Raw(&'a str),
    NameValue(&'a str, &'a dyn UriDisplay<Query>),
    Value(&'a dyn UriDisplay<Query>)
}

// Used by code generation.
#[doc(hidden)]
pub struct UriArguments<'a> {
    pub path: UriArgumentsKind<&'a [&'a dyn UriDisplay<Path>]>,
    pub query: Option<UriArgumentsKind<&'a [UriQueryArgument<'a>]>>,
}

// Used by code generation.
impl UriArguments<'_> {
    #[doc(hidden)]
    pub fn into_origin(self) -> Origin<'static> {
        use std::borrow::Cow;
        use self::{UriArgumentsKind::*, UriQueryArgument::*};

        let path: Cow<'static, str> = match self.path {
            Static(path) => path.into(),
            Dynamic(args) => {
                let mut string = String::from("/");
                {
                    let mut formatter = Formatter::<Path>::new(&mut string);
                    for value in args {
                        let _ = formatter.write_value(value);
                    }
                }

                string.into()
            }
        };

        let query: Option<Cow<'_, str>> = self.query.and_then(|q| match q {
            Static(query) => Some(query.into()),
            Dynamic(args) if args.is_empty() => None,
            Dynamic(args) => {
                let mut string = String::new();
                {
                    let mut f = Formatter::<Query>::new(&mut string);
                    for arg in args {
                        let _ = match arg {
                            Raw(v) => f.write_raw(v),
                            NameValue(n, v) => f.write_named_value(n, v),
                            Value(v) => f.write_value(v),
                        };
                    }
                }

                Some(string.into())
            }
        });

        Origin::new(path, query)
    }
}
