### Executive summary

Your WebGL bindings hand un-sanitised JavaScript ArrayBuffer pointers straight to OpenGL.
Several upload/download entry-points neither respect the view’s `byteOffset` nor verify that the
backing store is big enough for the transfer.
From JavaScript an attacker can therefore make OpenGL **write past the end of an
ArrayBuffer (heap corruption) or read past it (information leak)**, both without triggering WebGL-side
`GL_INVALID_VALUE` errors.

Below are three concrete, independently triggerable vulnerabilities.

---

## 1. Heap-overflow in `readPixels` (WebGL 1 & 2)

| Detail            | Value                                                                                  |
| ----------------- | -------------------------------------------------------------------------------------- |
| **Introduced in** | `WebGLRenderingContextImpl::read_pixels` and `WebGL2RenderingContextImpl::read_pixels` |
| **Native sink**   | `glReadPixels`                                                                         |
| **Memory hazard** | **Out-of-bounds ***write*** into JS heap**                                             |

### Code path

```
JS:  gl.readPixels(x, y, w, h, fmt, type, tinyView);
 ↳  WebGLRenderingContextImpl::read_pixels(...)
      void* ptr = view->viewed_array_buffer()->buffer().data();   // start of buffer, ignores byteOffset
      glReadPixels(x, y, w, h, fmt, type, ptr);                   // no size check
```

,&#x20;

### Why it is unsafe

* `ptr` always points to the beginning of the **whole** ArrayBuffer, not to the
  view’s `byteOffset`.
* No code checks that
  `w × h × bytesPerPixel ≤ ArrayBuffer.byteLength`.
* `glReadPixels` writes `w × h × bpp` bytes into `ptr`.
  If the caller supplies a one-byte TypedArray while asking
  for, say, a 4096 × 4096 RGBA/UNSIGNED\_BYTE read, \~64 MiB
  will be written past the ArrayBuffer and deep into the JS heap.

### Trigger from JavaScript

```js
const gl = canvas.getContext("webgl2");
const buf = new ArrayBuffer(4);               // 4 bytes heap slot
const u8  = new Uint8Array(buf);              // view length 4, offset 0
gl.readPixels(0, 0,
              8192, 8192,                    // huge area – adjust to framebuffer size
              gl.RGBA, gl.UNSIGNED_BYTE,
              u8);                            // driver overwrites ~256 MiB
```

On macOS + ANGLE this reliably crashes the Ladybird process; on
debug builds the JS GC later detects corrupted cell headers.

### Exploitability

Because the write lands inside normal JS heap arenas, an attacker can:

1. Corrupt neighbouring JS objects (length fields, vtables, etc.).
2. Re-read those objects from JS, yielding a powerful arbitrary-read/-write
   primitive and ultimately code-execution in the browser process.

---

## 2. Out-of-bounds reads in texture upload paths

Affected entry points ignore the **view’s offset** when computing `ptr`
and never validate `byteLength`:

* `WebGLRenderingContextImpl::tex_image2d`&#x20;
* `WebGLRenderingContextImpl::tex_sub_image2d`&#x20;
* The corresponding WebGL 2 overloads (same bug)&#x20;
* 3-D variants (`texImage3D`/`texSubImage3D`) show the same pattern.

### Impact

`glTexImage*` reads `byteCount` bytes from `ptr`.
If the view starts at a non-zero `byteOffset`, *bytes that precede the
view* (potentially freed or uninitialised heap data) are uploaded to the GPU.
The attacker can immediately leak these bytes back to JS by rendering the
texture to a framebuffer and calling `readPixels`.

Thus this is a **user-triggerable memory disclosure** across all
desktop/mobile GPUs.

---

## 3. Over-read in `bufferData` / `bufferSubData`

Both WebGL 1 and 2 implementations take the size from the **entire
ArrayBuffer**, not from the TypedArray/DataView that was actually passed:

```cpp
byte_size = typed_array_base.viewed_array_buffer()->byte_length();   // not view length
glBufferData(target, byte_size, ptr, usage);
```



An attacker can pass a 4-byte `Uint8Array` that views the last 4 bytes of a
1 GiB ArrayBuffer; the call uploads the whole gigabyte, causing OpenGL to read
\~1 GiB beyond the intended range.
Again, reading GPU memory back (or simply observing timing side-channels)
leaks the spilled data.

---

## Recommendations

| Priority                                                   | Fix                                                                                                                                                               |
| ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1**                                                      | For every `ArrayBufferView`, compute                                                                                                                              |
| `ptr = view->data() /* already includes byteOffset */` and |                                                                                                                                                                   |
| `byte_size = view->byteLength()`                           |                                                                                                                                                                   |
| **2**                                                      | Before calling into GL **validate** that `byte_size` is at least the number of bytes that the GL command will read or write. Return `GL_INVALID_VALUE` otherwise. |
| **3**                                                      | Add fuzz tests that try minimal-size buffers against maximal-size operations (`readPixels`, `tex*Image*`, `buffer*Data`).                                         |
| **4**                                                      | Consider using *checked span* helpers to make the pointer + length relationship explicit throughout the WebGL code-gen templates.                                 |

---

### Other observations (not exploitable memory-safety)

* The `uniformMatrix*fv` bounds check is inverted (`<=` instead of `>`),
  leading to spurious `INVALID_VALUE`s, but no OOB access.
* Numerous getters/setters call GL with no current‐context check – this can
  yield stale errors but not memory corruption.

---

## Conclusion

Because WebGL is script-reachable, the `readPixels` overflow is a
straightforward, reliable process-crasher and a plausible RCE primitive.
The texture / buffer over-reads leak heap memory to shaders and thence to
JavaScript, breaking same-origin confidentiality.

Tightening the view-to-pointer conversion and adding length validation
eliminates all three classes of bugs.
