# GIF en- and decoding library [![Build Status](https://travis-ci.org/image-rs/image-gif.svg?branch=master)](https://travis-ci.org/image-rs/image-gif)

GIF en- and decoder written in Rust ([API Documentation](https://docs.rs/gif/)).

# GIF encoding and decoding library

This library provides all functions necessary to de- and encode GIF files. 

## High level interface

The high level interface consists of the two types
[`Encoder`](https://docs.rs/gif/0.10.1/gif/struct.Encoder.html) and [`Decoder`](https://docs.rs/gif/0.10.1/gif/struct.Decoder.html).
They as builders for the actual en- and decoders and can be used to set various
options beforehand.

### Decoding GIF files

```rust
// Open the file
use std::fs::File;
use gif::SetParameter;
let mut decoder = gif::Decoder::new(File::open("tests/samples/sample_1.gif").unwrap());
// Configure the decoder such that it will expand the image to RGBA.
decoder.set(gif::ColorOutput::RGBA);
// Read the file header
let mut decoder = decoder.read_info().unwrap();
while let Some(frame) = decoder.read_next_frame().unwrap() {
    // Process every frame
}
```

### Encoding GIF files

The encoder can be used to save simple computer generated images:

```rust
use gif::{Frame, Encoder, Repeat, SetParameter};
use std::fs::File;
use std::borrow::Cow;

let color_map = &[0xFF, 0xFF, 0xFF, 0, 0, 0];
let (width, height) = (6, 6);
let beacon_states = [[
    0, 0, 0, 0, 0, 0,
    0, 1, 1, 0, 0, 0,
    0, 1, 1, 0, 0, 0,
    0, 0, 0, 1, 1, 0,
    0, 0, 0, 1, 1, 0,
    0, 0, 0, 0, 0, 0,
], [
    0, 0, 0, 0, 0, 0,
    0, 1, 1, 0, 0, 0,
    0, 1, 0, 0, 0, 0,
    0, 0, 0, 0, 1, 0,
    0, 0, 0, 1, 1, 0,
    0, 0, 0, 0, 0, 0,
]];
let mut image = File::create("target/beacon.gif").unwrap();
let mut encoder = Encoder::new(&mut image, width, height, color_map).unwrap();
encoder.set(Repeat::Infinite).unwrap();
for state in &beacon_states {
    let mut frame = Frame::default();
    frame.width = width;
    frame.height = height;
    frame.buffer = Cow::Borrowed(&*state);
    encoder.write_frame(&frame).unwrap();
}
```

[`Frame::from_*`](https://docs.rs/gif/0.10.1/gif/struct.Frame.html) can be used to convert a true color image to a paletted
image with a maximum of 256 colors:

```rust
use std::fs::File;

// Get pixel data from some source
let mut pixels: Vec<u8> = vec![0; 30_000];
// Create frame from data
let frame = gif::Frame::from_rgb(100, 100, &mut *pixels);
// Create encoder
let mut image = File::create("target/indexed_color.gif").unwrap();
let mut encoder = gif::Encoder::new(&mut image, frame.width, frame.height, &[]).unwrap();
// Write frame to file
encoder.write_frame(&frame).unwrap();
```
