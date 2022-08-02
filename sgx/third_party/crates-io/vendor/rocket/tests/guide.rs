#![feature(proc_macro_hygiene)]
#![feature(external_doc)]

#[allow(dead_code)]
mod test_guide {
    #[doc(include = "../../../site/guide/2-getting-started.md")]
    pub struct GuideGettingStart;

    /// ```rust
    /// assert_eq!(0, 1);
    /// ```
    struct Foo;
}

