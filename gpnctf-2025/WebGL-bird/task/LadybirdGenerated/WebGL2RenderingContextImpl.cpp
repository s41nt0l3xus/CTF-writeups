
#include <GLES3/gl3.h>

#include <LibJS/Runtime/ArrayBuffer.h>
#include <LibJS/Runtime/DataView.h>
#include <LibJS/Runtime/TypedArray.h>
#include <LibWeb/HTML/HTMLCanvasElement.h>
#include <LibWeb/HTML/HTMLImageElement.h>
#include <LibWeb/HTML/HTMLVideoElement.h>
#include <LibWeb/HTML/ImageBitmap.h>
#include <LibWeb/HTML/ImageData.h>
#include <LibWeb/WebGL/OpenGLContext.h>
#include <LibWeb/WebGL/WebGLActiveInfo.h>
#include <LibWeb/WebGL/WebGLBuffer.h>
#include <LibWeb/WebGL/WebGLFramebuffer.h>
#include <LibWeb/WebGL/WebGLProgram.h>
#include <LibWeb/WebGL/WebGLRenderbuffer.h>
#include <LibWeb/WebGL/WebGL2RenderingContextImpl.h>
#include <LibWeb/WebGL/WebGLSampler.h>
#include <LibWeb/WebGL/WebGLShader.h>
#include <LibWeb/WebGL/WebGLSync.h>
#include <LibWeb/WebGL/WebGLShaderPrecisionFormat.h>
#include <LibWeb/WebGL/WebGLTexture.h>
#include <LibWeb/WebGL/WebGLUniformLocation.h>
#include <LibWeb/WebGL/WebGLVertexArrayObject.h>
#include <LibWeb/WebIDL/Buffers.h>

namespace Web::WebGL {

static Vector<GLchar> null_terminated_string(StringView string)
{
    Vector<GLchar> result;
    for (auto c : string.bytes())
        result.append(c);
    result.append('\0');
    return result;
}

WebGL2RenderingContextImpl::WebGL2RenderingContextImpl(JS::Realm& realm, NonnullOwnPtr<OpenGLContext> context)
    : m_realm(realm)
    , m_context(move(context))
{
}


void WebGL2RenderingContextImpl::blit_framebuffer(WebIDL::Long src_x0, WebIDL::Long src_y0, WebIDL::Long src_x1, WebIDL::Long src_y1, WebIDL::Long dst_x0, WebIDL::Long dst_y0, WebIDL::Long dst_x1, WebIDL::Long dst_y1, WebIDL::UnsignedLong mask, WebIDL::UnsignedLong filter)
{
    m_context->make_current();
    glBlitFramebuffer(src_x0, src_y0, src_x1, src_y1, dst_x0, dst_y0, dst_x1, dst_y1, mask, filter);
}

void WebGL2RenderingContextImpl::read_buffer(WebIDL::UnsignedLong src)
{
    m_context->make_current();
    glReadBuffer(src);
}

JS::Value WebGL2RenderingContextImpl::get_internalformat_parameter(WebIDL::UnsignedLong target, WebIDL::UnsignedLong internalformat, WebIDL::UnsignedLong pname)
{
    m_context->make_current();

    switch (pname) {
    case GL_SAMPLES: {
        GLint num_sample_counts { 0 };
        glGetInternalformativ(target, internalformat, GL_NUM_SAMPLE_COUNTS, 1, &num_sample_counts);
        auto samples_buffer = MUST(ByteBuffer::create_zeroed(num_sample_counts * sizeof(GLint)));
        glGetInternalformativ(target, internalformat, GL_SAMPLES, num_sample_counts, reinterpret_cast<GLint*>(samples_buffer.data()));
        auto array_buffer = JS::ArrayBuffer::create(m_realm, move(samples_buffer));
        return JS::Int32Array::create(m_realm, num_sample_counts, array_buffer);
    }
    default:
        dbgln("Unknown WebGL internal format parameter name: {:x}", pname);
        set_error(GL_INVALID_ENUM);
        return JS::js_null();
    }
}

void WebGL2RenderingContextImpl::renderbuffer_storage_multisample(WebIDL::UnsignedLong target, WebIDL::Long samples, WebIDL::UnsignedLong internalformat, WebIDL::Long width, WebIDL::Long height)
{
    m_context->make_current();
    glRenderbufferStorageMultisample(target, samples, internalformat, width, height);
}

void WebGL2RenderingContextImpl::tex_storage2d(WebIDL::UnsignedLong target, WebIDL::Long levels, WebIDL::UnsignedLong internalformat, WebIDL::Long width, WebIDL::Long height)
{
    m_context->make_current();

    glTexStorage2D(target, levels, internalformat, width, height);
}

void WebGL2RenderingContextImpl::tex_storage3d(WebIDL::UnsignedLong target, WebIDL::Long levels, WebIDL::UnsignedLong internalformat, WebIDL::Long width, WebIDL::Long height, WebIDL::Long depth)
{
    m_context->make_current();
    glTexStorage3D(target, levels, internalformat, width, height, depth);
}

void WebGL2RenderingContextImpl::tex_image3d(WebIDL::UnsignedLong target, WebIDL::Long level, WebIDL::Long internalformat, WebIDL::Long width, WebIDL::Long height, WebIDL::Long depth, WebIDL::Long border, WebIDL::UnsignedLong format, WebIDL::UnsignedLong type, GC::Root<WebIDL::ArrayBufferView> src_data)
{
    m_context->make_current();

    void const* src_data_ptr = nullptr;
    if (src_data) {
        auto const& viewed_array_buffer = src_data->viewed_array_buffer();
        auto const& byte_buffer = viewed_array_buffer->buffer();
        src_data_ptr = byte_buffer.data();
    }
    glTexImage3D(target, level, internalformat, width, height, depth, border, format, type, src_data_ptr);
}

void WebGL2RenderingContextImpl::tex_image3d(WebIDL::UnsignedLong target, WebIDL::Long level, WebIDL::Long internalformat, WebIDL::Long width, WebIDL::Long height, WebIDL::Long depth, WebIDL::Long border, WebIDL::UnsignedLong format, WebIDL::UnsignedLong type, GC::Root<WebIDL::ArrayBufferView> src_data, WebIDL::UnsignedLongLong src_offset)
{
    m_context->make_current();

    void const* src_data_ptr = nullptr;
    if (src_data) {
        auto const& viewed_array_buffer = src_data->viewed_array_buffer();
        auto const& byte_buffer = viewed_array_buffer->buffer();
        src_data_ptr = byte_buffer.data() + src_offset;
    }
    glTexImage3D(target, level, internalformat, width, height, depth, border, format, type, src_data_ptr);
}

void WebGL2RenderingContextImpl::tex_sub_image3d(WebIDL::UnsignedLong target, WebIDL::Long level, WebIDL::Long xoffset, WebIDL::Long yoffset, WebIDL::Long zoffset, WebIDL::Long width, WebIDL::Long height, WebIDL::Long depth, WebIDL::UnsignedLong format, WebIDL::UnsignedLong type, GC::Root<WebIDL::ArrayBufferView> src_data, WebIDL::UnsignedLongLong src_offset)
{
    m_context->make_current();

    void const* pixels_ptr = nullptr;
    if (src_data) {
        auto const& viewed_array_buffer = src_data->viewed_array_buffer();
        auto const& byte_buffer = viewed_array_buffer->buffer();
        pixels_ptr = byte_buffer.data() + src_offset;
    }
    glTexSubImage3D(target, level, xoffset, yoffset, zoffset, width, height, depth, format, type, pixels_ptr);
}

void WebGL2RenderingContextImpl::draw_buffers(Vector<WebIDL::UnsignedLong> buffers)
{
    m_context->make_current();

    glDrawBuffers(buffers.size(), buffers.data());
}

GC::Root<WebGLSampler> WebGL2RenderingContextImpl::create_sampler()
{
    m_context->make_current();

    GLuint handle = 0;
    glGenSamplers(1, &handle);
    return WebGLSampler::create(m_realm, *this, handle);
}

void WebGL2RenderingContextImpl::bind_sampler(WebIDL::UnsignedLong unit, GC::Root<WebGLSampler> sampler)
{
    m_context->make_current();

    auto sampler_handle = 0;
    if (sampler) {
        auto handle_or_error = sampler->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return ;
        }
        sampler_handle = handle_or_error.release_value();
    }
    glBindSampler(unit, sampler_handle);
}

GC::Root<WebGLSync> WebGL2RenderingContextImpl::fence_sync(WebIDL::UnsignedLong condition, WebIDL::UnsignedLong flags)
{
    m_context->make_current();

    GLsync handle = glFenceSync(condition, flags);
    return WebGLSync::create(m_realm, *this, handle);
}

void WebGL2RenderingContextImpl::delete_sync(GC::Root<WebGLSync> sync)
{
    m_context->make_current();
    glDeleteSync((GLsync)(sync ? sync->sync_handle() : nullptr));
}

WebIDL::UnsignedLong WebGL2RenderingContextImpl::client_wait_sync(GC::Root<WebGLSync> sync, WebIDL::UnsignedLong flags, WebIDL::UnsignedLongLong timeout)
{
    m_context->make_current();
    return glClientWaitSync((GLsync)(sync ? sync->sync_handle() : nullptr), flags, timeout);
}

void WebGL2RenderingContextImpl::bind_buffer_base(WebIDL::UnsignedLong target, WebIDL::UnsignedLong index, GC::Root<WebGLBuffer> buffer)
{
    m_context->make_current();

    auto buffer_handle = 0;
    if (buffer) {
        auto handle_or_error = buffer->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return ;
        }
        buffer_handle = handle_or_error.release_value();
    }
    glBindBufferBase(target, index, buffer_handle);
}

GC::Root<WebGLVertexArrayObject> WebGL2RenderingContextImpl::create_vertex_array()
{
    m_context->make_current();

    GLuint handle = 0;
    glGenVertexArrays(1, &handle);
    return WebGLVertexArrayObject::create(m_realm, *this, handle);
}

void WebGL2RenderingContextImpl::delete_vertex_array(GC::Root<WebGLVertexArrayObject> vertex_array)
{
    m_context->make_current();

    GLuint vertex_array_handle = 0;
    if (vertex_array) {
        auto handle_or_error = vertex_array->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return ;
        }
        vertex_array_handle = handle_or_error.release_value();
    }

    glDeleteVertexArrays(1, &vertex_array_handle);
}

bool WebGL2RenderingContextImpl::is_vertex_array(GC::Root<WebGLVertexArrayObject> vertex_array)
{
    m_context->make_current();

    auto vertex_array_handle = 0;
    if (vertex_array) {
        auto handle_or_error = vertex_array->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return false;
        }
        vertex_array_handle = handle_or_error.release_value();
    }
    return glIsVertexArray(vertex_array_handle);
}

void WebGL2RenderingContextImpl::bind_vertex_array(GC::Root<WebGLVertexArrayObject> array)
{
    m_context->make_current();

    auto array_handle = 0;
    if (array) {
        auto handle_or_error = array->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return ;
        }
        array_handle = handle_or_error.release_value();
    }
    glBindVertexArray(array_handle);
}

void WebGL2RenderingContextImpl::buffer_data(WebIDL::UnsignedLong target, WebIDL::LongLong size, WebIDL::UnsignedLong usage)
{
    m_context->make_current();

    glBufferData(target, size, 0, usage);
}

void WebGL2RenderingContextImpl::buffer_data(WebIDL::UnsignedLong target, GC::Root<WebIDL::BufferSource> src_data, WebIDL::UnsignedLong usage)
{
    m_context->make_current();

    void const* ptr = nullptr;
    size_t byte_size = 0;
    if (src_data->is_typed_array_base()) {
        auto& typed_array_base = static_cast<JS::TypedArrayBase&>(*src_data->raw_object());
        ptr = typed_array_base.viewed_array_buffer()->buffer().data();
        byte_size = typed_array_base.viewed_array_buffer()->byte_length();
    } else if (src_data->is_data_view()) {
        auto& data_view = static_cast<JS::DataView&>(*src_data->raw_object());
        ptr = data_view.viewed_array_buffer()->buffer().data();
        byte_size = data_view.viewed_array_buffer()->byte_length();
    } else if (src_data->is_array_buffer()) {
        auto& array_buffer = static_cast<JS::ArrayBuffer&>(*src_data->raw_object());
        ptr = array_buffer.buffer().data();
        byte_size = array_buffer.byte_length();
    } else {
        VERIFY_NOT_REACHED();
    }
    glBufferData(target, byte_size, ptr, usage);
}

void WebGL2RenderingContextImpl::buffer_sub_data(WebIDL::UnsignedLong target, WebIDL::LongLong dst_byte_offset, GC::Root<WebIDL::BufferSource> src_data)
{
    m_context->make_current();

    void const* ptr = nullptr;
    size_t byte_size = 0;
    if (src_data->is_typed_array_base()) {
        auto& typed_array_base = static_cast<JS::TypedArrayBase&>(*src_data->raw_object());
        ptr = typed_array_base.viewed_array_buffer()->buffer().data();
        byte_size = typed_array_base.viewed_array_buffer()->byte_length();
    } else if (src_data->is_data_view()) {
        auto& data_view = static_cast<JS::DataView&>(*src_data->raw_object());
        ptr = data_view.viewed_array_buffer()->buffer().data();
        byte_size = data_view.viewed_array_buffer()->byte_length();
    } else if (src_data->is_array_buffer()) {
        auto& array_buffer = static_cast<JS::ArrayBuffer&>(*src_data->raw_object());
        ptr = array_buffer.buffer().data();
        byte_size = array_buffer.byte_length();
    } else {
        VERIFY_NOT_REACHED();
    }
    glBufferSubData(target, dst_byte_offset, byte_size, ptr);
}

void WebGL2RenderingContextImpl::tex_image2d(WebIDL::UnsignedLong target, WebIDL::Long level, WebIDL::Long internalformat, WebIDL::Long width, WebIDL::Long height, WebIDL::Long border, WebIDL::UnsignedLong format, WebIDL::UnsignedLong type, GC::Root<WebIDL::ArrayBufferView> pixels)
{
    m_context->make_current();

    void const* pixels_ptr = nullptr;
    if (pixels) {
        auto const& viewed_array_buffer = pixels->viewed_array_buffer();
        auto const& byte_buffer = viewed_array_buffer->buffer();
        pixels_ptr = byte_buffer.data();
    }
    glTexImage2D(target, level, internalformat, width, height, border, format, type, pixels_ptr);
}

void WebGL2RenderingContextImpl::tex_image2d(WebIDL::UnsignedLong target, WebIDL::Long level, WebIDL::Long internalformat, WebIDL::UnsignedLong format, WebIDL::UnsignedLong type, Variant<GC::Root<ImageBitmap>, GC::Root<ImageData>, GC::Root<HTMLImageElement>, GC::Root<HTMLCanvasElement>, GC::Root<HTMLVideoElement>> source)
{
    m_context->make_current();

    auto bitmap = source.visit(
        [](GC::Root<HTMLImageElement> const& source) -> RefPtr<Gfx::ImmutableBitmap> {
            return source->immutable_bitmap();
        },
        [](GC::Root<HTMLCanvasElement> const& source) -> RefPtr<Gfx::ImmutableBitmap> {
            auto surface = source->surface();
            if (!surface)
                return {};
            auto bitmap = MUST(Gfx::Bitmap::create(Gfx::BitmapFormat::RGBA8888, Gfx::AlphaType::Premultiplied, surface->size()));
            surface->read_into_bitmap(*bitmap);
            return Gfx::ImmutableBitmap::create(*bitmap);
        },
        [](GC::Root<HTMLVideoElement> const& source) -> RefPtr<Gfx::ImmutableBitmap> {
            return Gfx::ImmutableBitmap::create(*source->bitmap());
        },
        [](GC::Root<ImageBitmap> const& source) -> RefPtr<Gfx::ImmutableBitmap> {
            return Gfx::ImmutableBitmap::create(*source->bitmap());
        },
        [](GC::Root<ImageData> const& source) -> RefPtr<Gfx::ImmutableBitmap> {
            return Gfx::ImmutableBitmap::create(source->bitmap());
        });
    if (!bitmap)
        return;

    void const* pixels_ptr = bitmap->bitmap()->begin();
    int width = bitmap->width();
    int height = bitmap->height();
    glTexImage2D(target, level, internalformat, width, height, 0, format, type, pixels_ptr);
}

void WebGL2RenderingContextImpl::tex_sub_image2d(WebIDL::UnsignedLong target, WebIDL::Long level, WebIDL::Long xoffset, WebIDL::Long yoffset, WebIDL::Long width, WebIDL::Long height, WebIDL::UnsignedLong format, WebIDL::UnsignedLong type, GC::Root<WebIDL::ArrayBufferView> pixels)
{
    m_context->make_current();

    void const* pixels_ptr = nullptr;
    if (pixels) {
        auto const& viewed_array_buffer = pixels->viewed_array_buffer();
        auto const& byte_buffer = viewed_array_buffer->buffer();
        pixels_ptr = byte_buffer.data();
    }
    glTexSubImage2D(target, level, xoffset, yoffset, width, height, format, type, pixels_ptr);
}

void WebGL2RenderingContextImpl::tex_image2d(WebIDL::UnsignedLong target, WebIDL::Long level, WebIDL::Long internalformat, WebIDL::Long width, WebIDL::Long height, WebIDL::Long border, WebIDL::UnsignedLong format, WebIDL::UnsignedLong type, GC::Root<WebIDL::ArrayBufferView> src_data, WebIDL::UnsignedLongLong src_offset)
{
    m_context->make_current();

    void const* pixels_ptr = nullptr;
    if (src_data) {
        auto const& viewed_array_buffer = src_data->viewed_array_buffer();
        auto const& byte_buffer = viewed_array_buffer->buffer();
        pixels_ptr = byte_buffer.data() + src_offset;
    }
    glTexImage2D(target, level, internalformat, width, height, border, format, type, pixels_ptr);
}

void WebGL2RenderingContextImpl::tex_sub_image2d(WebIDL::UnsignedLong target, WebIDL::Long level, WebIDL::Long xoffset, WebIDL::Long yoffset, WebIDL::Long width, WebIDL::Long height, WebIDL::UnsignedLong format, WebIDL::UnsignedLong type, GC::Root<WebIDL::ArrayBufferView> src_data, WebIDL::UnsignedLongLong src_offset)
{
    m_context->make_current();

    void const* pixels_ptr = nullptr;
    if (src_data) {
        auto const& viewed_array_buffer = src_data->viewed_array_buffer();
        auto const& byte_buffer = viewed_array_buffer->buffer();
        pixels_ptr = byte_buffer.data() + src_offset;
    }
    glTexSubImage2D(target, level, xoffset, yoffset, width, height, format, type, pixels_ptr);
}

void WebGL2RenderingContextImpl::uniform1fv(GC::Root<WebGLUniformLocation> location, Variant<GC::Root<WebIDL::BufferSource>, Vector<float>> v, WebIDL::UnsignedLongLong src_offset, WebIDL::UnsignedLong src_length)
{
    m_context->make_current();

    float const* data = nullptr;
    size_t count = 0;
    if (v.has<Vector<float>>()) {
        auto& vector = v.get<Vector<float>>();
        data = vector.data();
        count = vector.size();
    } else if (v.has<GC::Root<WebIDL::BufferSource>>()) {
        auto& typed_array_base = static_cast<JS::TypedArrayBase&>(*v.get<GC::Root<WebIDL::BufferSource>>()->raw_object());
        auto& typed_array = verify_cast<JS::Float32Array>(typed_array_base);
        data = typed_array.data().data();
        count = typed_array.array_length().length();
    } else {
        VERIFY_NOT_REACHED();
    }

    data += src_offset;
    if (src_length == 0) {
        count -= src_offset;
    }

    if (src_offset + src_length <= count) {
        set_error(GL_INVALID_VALUE);
        return;
    }

    glUniform1fv(location->handle(), count / 1, data);
}

void WebGL2RenderingContextImpl::uniform2fv(GC::Root<WebGLUniformLocation> location, Variant<GC::Root<WebIDL::BufferSource>, Vector<float>> v, WebIDL::UnsignedLongLong src_offset, WebIDL::UnsignedLong src_length)
{
    m_context->make_current();

    float const* data = nullptr;
    size_t count = 0;
    if (v.has<Vector<float>>()) {
        auto& vector = v.get<Vector<float>>();
        data = vector.data();
        count = vector.size();
    } else if (v.has<GC::Root<WebIDL::BufferSource>>()) {
        auto& typed_array_base = static_cast<JS::TypedArrayBase&>(*v.get<GC::Root<WebIDL::BufferSource>>()->raw_object());
        auto& typed_array = verify_cast<JS::Float32Array>(typed_array_base);
        data = typed_array.data().data();
        count = typed_array.array_length().length();
    } else {
        VERIFY_NOT_REACHED();
    }

    data += src_offset;
    if (src_length == 0) {
        count -= src_offset;
    }

    if (src_offset + src_length <= count) {
        set_error(GL_INVALID_VALUE);
        return;
    }

    glUniform2fv(location->handle(), count / 2, data);
}

void WebGL2RenderingContextImpl::uniform3fv(GC::Root<WebGLUniformLocation> location, Variant<GC::Root<WebIDL::BufferSource>, Vector<float>> v, WebIDL::UnsignedLongLong src_offset, WebIDL::UnsignedLong src_length)
{
    m_context->make_current();

    float const* data = nullptr;
    size_t count = 0;
    if (v.has<Vector<float>>()) {
        auto& vector = v.get<Vector<float>>();
        data = vector.data();
        count = vector.size();
    } else if (v.has<GC::Root<WebIDL::BufferSource>>()) {
        auto& typed_array_base = static_cast<JS::TypedArrayBase&>(*v.get<GC::Root<WebIDL::BufferSource>>()->raw_object());
        auto& typed_array = verify_cast<JS::Float32Array>(typed_array_base);
        data = typed_array.data().data();
        count = typed_array.array_length().length();
    } else {
        VERIFY_NOT_REACHED();
    }

    data += src_offset;
    if (src_length == 0) {
        count -= src_offset;
    }

    if (src_offset + src_length <= count) {
        set_error(GL_INVALID_VALUE);
        return;
    }

    glUniform3fv(location->handle(), count / 3, data);
}

void WebGL2RenderingContextImpl::uniform4fv(GC::Root<WebGLUniformLocation> location, Variant<GC::Root<WebIDL::BufferSource>, Vector<float>> v, WebIDL::UnsignedLongLong src_offset, WebIDL::UnsignedLong src_length)
{
    m_context->make_current();

    float const* data = nullptr;
    size_t count = 0;
    if (v.has<Vector<float>>()) {
        auto& vector = v.get<Vector<float>>();
        data = vector.data();
        count = vector.size();
    } else if (v.has<GC::Root<WebIDL::BufferSource>>()) {
        auto& typed_array_base = static_cast<JS::TypedArrayBase&>(*v.get<GC::Root<WebIDL::BufferSource>>()->raw_object());
        auto& typed_array = verify_cast<JS::Float32Array>(typed_array_base);
        data = typed_array.data().data();
        count = typed_array.array_length().length();
    } else {
        VERIFY_NOT_REACHED();
    }

    data += src_offset;
    if (src_length == 0) {
        count -= src_offset;
    }

    if (src_offset + src_length <= count) {
        set_error(GL_INVALID_VALUE);
        return;
    }

    glUniform4fv(location->handle(), count / 4, data);
}

void WebGL2RenderingContextImpl::uniform1iv(GC::Root<WebGLUniformLocation> location, Variant<GC::Root<WebIDL::BufferSource>, Vector<WebIDL::Long>> v, WebIDL::UnsignedLongLong src_offset, WebIDL::UnsignedLong src_length)
{
    m_context->make_current();

    int const* data = nullptr;
    size_t count = 0;
    if (v.has<Vector<int>>()) {
        auto& vector = v.get<Vector<int>>();
        data = vector.data();
        count = vector.size();
    } else if (v.has<GC::Root<WebIDL::BufferSource>>()) {
        auto& typed_array_base = static_cast<JS::TypedArrayBase&>(*v.get<GC::Root<WebIDL::BufferSource>>()->raw_object());
        auto& typed_array = verify_cast<JS::Int32Array>(typed_array_base);
        data = typed_array.data().data();
        count = typed_array.array_length().length();
    } else {
        VERIFY_NOT_REACHED();
    }

    data += src_offset;
    if (src_length == 0) {
        count -= src_offset;
    }

    if (src_offset + src_length <= count) {
        set_error(GL_INVALID_VALUE);
        return;
    }

    glUniform1iv(location->handle(), count / 1, data);
}

void WebGL2RenderingContextImpl::uniform2iv(GC::Root<WebGLUniformLocation> location, Variant<GC::Root<WebIDL::BufferSource>, Vector<WebIDL::Long>> v, WebIDL::UnsignedLongLong src_offset, WebIDL::UnsignedLong src_length)
{
    m_context->make_current();

    int const* data = nullptr;
    size_t count = 0;
    if (v.has<Vector<int>>()) {
        auto& vector = v.get<Vector<int>>();
        data = vector.data();
        count = vector.size();
    } else if (v.has<GC::Root<WebIDL::BufferSource>>()) {
        auto& typed_array_base = static_cast<JS::TypedArrayBase&>(*v.get<GC::Root<WebIDL::BufferSource>>()->raw_object());
        auto& typed_array = verify_cast<JS::Int32Array>(typed_array_base);
        data = typed_array.data().data();
        count = typed_array.array_length().length();
    } else {
        VERIFY_NOT_REACHED();
    }

    data += src_offset;
    if (src_length == 0) {
        count -= src_offset;
    }

    if (src_offset + src_length <= count) {
        set_error(GL_INVALID_VALUE);
        return;
    }

    glUniform2iv(location->handle(), count / 2, data);
}

void WebGL2RenderingContextImpl::uniform3iv(GC::Root<WebGLUniformLocation> location, Variant<GC::Root<WebIDL::BufferSource>, Vector<WebIDL::Long>> v, WebIDL::UnsignedLongLong src_offset, WebIDL::UnsignedLong src_length)
{
    m_context->make_current();

    int const* data = nullptr;
    size_t count = 0;
    if (v.has<Vector<int>>()) {
        auto& vector = v.get<Vector<int>>();
        data = vector.data();
        count = vector.size();
    } else if (v.has<GC::Root<WebIDL::BufferSource>>()) {
        auto& typed_array_base = static_cast<JS::TypedArrayBase&>(*v.get<GC::Root<WebIDL::BufferSource>>()->raw_object());
        auto& typed_array = verify_cast<JS::Int32Array>(typed_array_base);
        data = typed_array.data().data();
        count = typed_array.array_length().length();
    } else {
        VERIFY_NOT_REACHED();
    }

    data += src_offset;
    if (src_length == 0) {
        count -= src_offset;
    }

    if (src_offset + src_length <= count) {
        set_error(GL_INVALID_VALUE);
        return;
    }

    glUniform3iv(location->handle(), count / 3, data);
}

void WebGL2RenderingContextImpl::uniform4iv(GC::Root<WebGLUniformLocation> location, Variant<GC::Root<WebIDL::BufferSource>, Vector<WebIDL::Long>> v, WebIDL::UnsignedLongLong src_offset, WebIDL::UnsignedLong src_length)
{
    m_context->make_current();

    int const* data = nullptr;
    size_t count = 0;
    if (v.has<Vector<int>>()) {
        auto& vector = v.get<Vector<int>>();
        data = vector.data();
        count = vector.size();
    } else if (v.has<GC::Root<WebIDL::BufferSource>>()) {
        auto& typed_array_base = static_cast<JS::TypedArrayBase&>(*v.get<GC::Root<WebIDL::BufferSource>>()->raw_object());
        auto& typed_array = verify_cast<JS::Int32Array>(typed_array_base);
        data = typed_array.data().data();
        count = typed_array.array_length().length();
    } else {
        VERIFY_NOT_REACHED();
    }

    data += src_offset;
    if (src_length == 0) {
        count -= src_offset;
    }

    if (src_offset + src_length <= count) {
        set_error(GL_INVALID_VALUE);
        return;
    }

    glUniform4iv(location->handle(), count / 4, data);
}

void WebGL2RenderingContextImpl::uniform_matrix2fv(GC::Root<WebGLUniformLocation> location, bool transpose, Variant<GC::Root<WebIDL::BufferSource>, Vector<float>> data, WebIDL::UnsignedLongLong src_offset, WebIDL::UnsignedLong src_length)
{
    m_context->make_current();

    auto matrix_size = 2 * 2;
    float const* raw_data = nullptr;
    u64 count = 0;
    if (data.has<Vector<float>>()) {
        auto& vector_data = data.get<Vector<float>>();
        raw_data = vector_data.data();
        count = vector_data.size() / matrix_size;
    } else {
        auto& typed_array_base = static_cast<JS::TypedArrayBase&>(*data.get<GC::Root<WebIDL::BufferSource>>()->raw_object());
        auto& float32_array = verify_cast<JS::Float32Array>(typed_array_base);
        raw_data = float32_array.data().data();
        count = float32_array.array_length().length() / matrix_size;
    }

    raw_data += src_offset;
    if (src_length == 0) {
        count -= src_offset;
    }

    if (src_offset + src_length <= count) {
        set_error(GL_INVALID_VALUE);
        return;
    }

    glUniformMatrix2fv(location->handle(), count, transpose, raw_data);
}

void WebGL2RenderingContextImpl::uniform_matrix3fv(GC::Root<WebGLUniformLocation> location, bool transpose, Variant<GC::Root<WebIDL::BufferSource>, Vector<float>> data, WebIDL::UnsignedLongLong src_offset, WebIDL::UnsignedLong src_length)
{
    m_context->make_current();

    auto matrix_size = 3 * 3;
    float const* raw_data = nullptr;
    u64 count = 0;
    if (data.has<Vector<float>>()) {
        auto& vector_data = data.get<Vector<float>>();
        raw_data = vector_data.data();
        count = vector_data.size() / matrix_size;
    } else {
        auto& typed_array_base = static_cast<JS::TypedArrayBase&>(*data.get<GC::Root<WebIDL::BufferSource>>()->raw_object());
        auto& float32_array = verify_cast<JS::Float32Array>(typed_array_base);
        raw_data = float32_array.data().data();
        count = float32_array.array_length().length() / matrix_size;
    }

    raw_data += src_offset;
    if (src_length == 0) {
        count -= src_offset;
    }

    if (src_offset + src_length <= count) {
        set_error(GL_INVALID_VALUE);
        return;
    }

    glUniformMatrix3fv(location->handle(), count, transpose, raw_data);
}

void WebGL2RenderingContextImpl::uniform_matrix4fv(GC::Root<WebGLUniformLocation> location, bool transpose, Variant<GC::Root<WebIDL::BufferSource>, Vector<float>> data, WebIDL::UnsignedLongLong src_offset, WebIDL::UnsignedLong src_length)
{
    m_context->make_current();

    auto matrix_size = 4 * 4;
    float const* raw_data = nullptr;
    u64 count = 0;
    if (data.has<Vector<float>>()) {
        auto& vector_data = data.get<Vector<float>>();
        raw_data = vector_data.data();
        count = vector_data.size() / matrix_size;
    } else {
        auto& typed_array_base = static_cast<JS::TypedArrayBase&>(*data.get<GC::Root<WebIDL::BufferSource>>()->raw_object());
        auto& float32_array = verify_cast<JS::Float32Array>(typed_array_base);
        raw_data = float32_array.data().data();
        count = float32_array.array_length().length() / matrix_size;
    }

    raw_data += src_offset;
    if (src_length == 0) {
        count -= src_offset;
    }

    if (src_offset + src_length <= count) {
        set_error(GL_INVALID_VALUE);
        return;
    }

    glUniformMatrix4fv(location->handle(), count, transpose, raw_data);
}

void WebGL2RenderingContextImpl::read_pixels(WebIDL::Long x, WebIDL::Long y, WebIDL::Long width, WebIDL::Long height, WebIDL::UnsignedLong format, WebIDL::UnsignedLong type, GC::Root<WebIDL::ArrayBufferView> pixels)
{
    m_context->make_current();

    if (!pixels) {
        return;
    }

    void *ptr = nullptr;
    if (pixels->is_data_view()) {
        auto& data_view = static_cast<JS::DataView&>(*pixels->raw_object());
        ptr = data_view.viewed_array_buffer()->buffer().data();
    } else if (pixels->is_typed_array_base()) {
        auto& typed_array_base = static_cast<JS::TypedArrayBase&>(*pixels->raw_object());
        ptr = typed_array_base.viewed_array_buffer()->buffer().data();
    } else {
        VERIFY_NOT_REACHED();
    }

    glReadPixels(x, y, width, height, format, type, ptr);
}

void WebGL2RenderingContextImpl::active_texture(WebIDL::UnsignedLong texture)
{
    m_context->make_current();
    glActiveTexture(texture);
}

void WebGL2RenderingContextImpl::attach_shader(GC::Root<WebGLProgram> program, GC::Root<WebGLShader> shader)
{
    m_context->make_current();

    auto program_handle = 0;
    if (program) {
        auto handle_or_error = program->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return ;
        }
        program_handle = handle_or_error.release_value();
    }

    auto shader_handle = 0;
    if (shader) {
        auto handle_or_error = shader->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return ;
        }
        shader_handle = handle_or_error.release_value();
    }
    glAttachShader(program_handle, shader_handle);
}

void WebGL2RenderingContextImpl::bind_attrib_location(GC::Root<WebGLProgram> program, WebIDL::UnsignedLong index, String name)
{
    m_context->make_current();

    auto program_handle = 0;
    if (program) {
        auto handle_or_error = program->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return ;
        }
        program_handle = handle_or_error.release_value();
    }

    auto name_null_terminated = null_terminated_string(name);
    glBindAttribLocation(program_handle, index, name_null_terminated.data());
}

void WebGL2RenderingContextImpl::bind_buffer(WebIDL::UnsignedLong target, GC::Root<WebGLBuffer> buffer)
{
    m_context->make_current();

    auto buffer_handle = 0;
    if (buffer) {
        auto handle_or_error = buffer->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return ;
        }
        buffer_handle = handle_or_error.release_value();
    }
    glBindBuffer(target, buffer_handle);
}

void WebGL2RenderingContextImpl::bind_framebuffer(WebIDL::UnsignedLong target, GC::Root<WebGLFramebuffer> framebuffer)
{
    m_context->make_current();

    auto framebuffer_handle = 0;
    if (framebuffer) {
        auto handle_or_error = framebuffer->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return ;
        }
        framebuffer_handle = handle_or_error.release_value();
    }
    glBindFramebuffer(target, framebuffer_handle);
}

void WebGL2RenderingContextImpl::bind_renderbuffer(WebIDL::UnsignedLong target, GC::Root<WebGLRenderbuffer> renderbuffer)
{
    m_context->make_current();

    auto renderbuffer_handle = 0;
    if (renderbuffer) {
        auto handle_or_error = renderbuffer->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return ;
        }
        renderbuffer_handle = handle_or_error.release_value();
    }
    glBindRenderbuffer(target, renderbuffer_handle);
}

void WebGL2RenderingContextImpl::bind_texture(WebIDL::UnsignedLong target, GC::Root<WebGLTexture> texture)
{
    m_context->make_current();

    auto texture_handle = 0;
    if (texture) {
        auto handle_or_error = texture->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return ;
        }
        texture_handle = handle_or_error.release_value();
    }
    glBindTexture(target, texture_handle);
}

void WebGL2RenderingContextImpl::blend_color(float red, float green, float blue, float alpha)
{
    m_context->make_current();
    glBlendColor(red, green, blue, alpha);
}

void WebGL2RenderingContextImpl::blend_equation(WebIDL::UnsignedLong mode)
{
    m_context->make_current();
    glBlendEquation(mode);
}

void WebGL2RenderingContextImpl::blend_equation_separate(WebIDL::UnsignedLong mode_rgb, WebIDL::UnsignedLong mode_alpha)
{
    m_context->make_current();
    glBlendEquationSeparate(mode_rgb, mode_alpha);
}

void WebGL2RenderingContextImpl::blend_func(WebIDL::UnsignedLong sfactor, WebIDL::UnsignedLong dfactor)
{
    m_context->make_current();
    glBlendFunc(sfactor, dfactor);
}

void WebGL2RenderingContextImpl::blend_func_separate(WebIDL::UnsignedLong src_rgb, WebIDL::UnsignedLong dst_rgb, WebIDL::UnsignedLong src_alpha, WebIDL::UnsignedLong dst_alpha)
{
    m_context->make_current();
    glBlendFuncSeparate(src_rgb, dst_rgb, src_alpha, dst_alpha);
}

WebIDL::UnsignedLong WebGL2RenderingContextImpl::check_framebuffer_status(WebIDL::UnsignedLong target)
{
    m_context->make_current();
    return glCheckFramebufferStatus(target);
}

void WebGL2RenderingContextImpl::clear(WebIDL::UnsignedLong mask)
{
    m_context->make_current();
    glClear(mask);
}

void WebGL2RenderingContextImpl::clear_color(float red, float green, float blue, float alpha)
{
    m_context->make_current();
    m_context->notify_content_will_change();
    needs_to_present();
    glClearColor(red, green, blue, alpha);
}

void WebGL2RenderingContextImpl::clear_depth(float depth)
{
    m_context->make_current();
    glClearDepthf(depth);
}

void WebGL2RenderingContextImpl::clear_stencil(WebIDL::Long s)
{
    m_context->make_current();
    glClearStencil(s);
}

void WebGL2RenderingContextImpl::color_mask(bool red, bool green, bool blue, bool alpha)
{
    m_context->make_current();
    glColorMask(red, green, blue, alpha);
}

void WebGL2RenderingContextImpl::compile_shader(GC::Root<WebGLShader> shader)
{
    m_context->make_current();

    auto shader_handle = 0;
    if (shader) {
        auto handle_or_error = shader->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return ;
        }
        shader_handle = handle_or_error.release_value();
    }
    glCompileShader(shader_handle);
}

GC::Root<WebGLBuffer> WebGL2RenderingContextImpl::create_buffer()
{
    m_context->make_current();

    GLuint handle = 0;
    glGenBuffers(1, &handle);
    return WebGLBuffer::create(m_realm, *this, handle);
}

GC::Root<WebGLFramebuffer> WebGL2RenderingContextImpl::create_framebuffer()
{
    m_context->make_current();

    GLuint handle = 0;
    glGenFramebuffers(1, &handle);
    return WebGLFramebuffer::create(m_realm, *this, handle);
}

GC::Root<WebGLProgram> WebGL2RenderingContextImpl::create_program()
{
    m_context->make_current();
    return WebGLProgram::create(m_realm, *this, glCreateProgram());
}

GC::Root<WebGLRenderbuffer> WebGL2RenderingContextImpl::create_renderbuffer()
{
    m_context->make_current();

    GLuint handle = 0;
    glGenRenderbuffers(1, &handle);
    return WebGLRenderbuffer::create(m_realm, *this, handle);
}

GC::Root<WebGLShader> WebGL2RenderingContextImpl::create_shader(WebIDL::UnsignedLong type)
{
    m_context->make_current();
    return WebGLShader::create(m_realm, *this, glCreateShader(type));
}

GC::Root<WebGLTexture> WebGL2RenderingContextImpl::create_texture()
{
    m_context->make_current();

    GLuint handle = 0;
    glGenTextures(1, &handle);
    return WebGLTexture::create(m_realm, *this, handle);
}

void WebGL2RenderingContextImpl::cull_face(WebIDL::UnsignedLong mode)
{
    m_context->make_current();
    glCullFace(mode);
}

void WebGL2RenderingContextImpl::delete_buffer(GC::Root<WebGLBuffer> buffer)
{
    m_context->make_current();

    GLuint buffer_handle = 0;
    if (buffer) {
        auto handle_or_error = buffer->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return ;
        }
        buffer_handle = handle_or_error.release_value();
    }

    glDeleteBuffers(1, &buffer_handle);
}

void WebGL2RenderingContextImpl::delete_framebuffer(GC::Root<WebGLFramebuffer> framebuffer)
{
    m_context->make_current();

    GLuint framebuffer_handle = 0;
    if (framebuffer) {
        auto handle_or_error = framebuffer->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return ;
        }
        framebuffer_handle = handle_or_error.release_value();
    }

    glDeleteFramebuffers(1, &framebuffer_handle);
}

void WebGL2RenderingContextImpl::delete_program(GC::Root<WebGLProgram> program)
{
    m_context->make_current();

    auto program_handle = 0;
    if (program) {
        auto handle_or_error = program->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return ;
        }
        program_handle = handle_or_error.release_value();
    }
    glDeleteProgram(program_handle);
}

void WebGL2RenderingContextImpl::delete_shader(GC::Root<WebGLShader> shader)
{
    m_context->make_current();

    auto shader_handle = 0;
    if (shader) {
        auto handle_or_error = shader->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return ;
        }
        shader_handle = handle_or_error.release_value();
    }
    glDeleteShader(shader_handle);
}

void WebGL2RenderingContextImpl::delete_texture(GC::Root<WebGLTexture> texture)
{
    m_context->make_current();

    GLuint texture_handle = 0;
    if (texture) {
        auto handle_or_error = texture->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return ;
        }
        texture_handle = handle_or_error.release_value();
    }

    glDeleteTextures(1, &texture_handle);
}

void WebGL2RenderingContextImpl::depth_func(WebIDL::UnsignedLong func)
{
    m_context->make_current();
    glDepthFunc(func);
}

void WebGL2RenderingContextImpl::depth_mask(bool flag)
{
    m_context->make_current();
    glDepthMask(flag);
}

void WebGL2RenderingContextImpl::depth_range(float z_near, float z_far)
{
    m_context->make_current();
    glDepthRangef(z_near, z_far);
}

void WebGL2RenderingContextImpl::detach_shader(GC::Root<WebGLProgram> program, GC::Root<WebGLShader> shader)
{
    m_context->make_current();

    auto program_handle = 0;
    if (program) {
        auto handle_or_error = program->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return ;
        }
        program_handle = handle_or_error.release_value();
    }

    auto shader_handle = 0;
    if (shader) {
        auto handle_or_error = shader->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return ;
        }
        shader_handle = handle_or_error.release_value();
    }
    glDetachShader(program_handle, shader_handle);
}

void WebGL2RenderingContextImpl::disable(WebIDL::UnsignedLong cap)
{
    m_context->make_current();
    glDisable(cap);
}

void WebGL2RenderingContextImpl::disable_vertex_attrib_array(WebIDL::UnsignedLong index)
{
    m_context->make_current();
    glDisableVertexAttribArray(index);
}

void WebGL2RenderingContextImpl::draw_arrays(WebIDL::UnsignedLong mode, WebIDL::Long first, WebIDL::Long count)
{
    m_context->make_current();
    m_context->notify_content_will_change();
    needs_to_present();
    glDrawArrays(mode, first, count);
}

void WebGL2RenderingContextImpl::draw_elements(WebIDL::UnsignedLong mode, WebIDL::Long count, WebIDL::UnsignedLong type, WebIDL::LongLong offset)
{
    m_context->make_current();
    m_context->notify_content_will_change();

    glDrawElements(mode, count, type, reinterpret_cast<void*>(offset));
    needs_to_present();
}

void WebGL2RenderingContextImpl::enable(WebIDL::UnsignedLong cap)
{
    m_context->make_current();
    glEnable(cap);
}

void WebGL2RenderingContextImpl::enable_vertex_attrib_array(WebIDL::UnsignedLong index)
{
    m_context->make_current();
    glEnableVertexAttribArray(index);
}

void WebGL2RenderingContextImpl::finish()
{
    m_context->make_current();
    glFinish();
}

void WebGL2RenderingContextImpl::flush()
{
    m_context->make_current();
    glFlush();
}

void WebGL2RenderingContextImpl::framebuffer_renderbuffer(WebIDL::UnsignedLong target, WebIDL::UnsignedLong attachment, WebIDL::UnsignedLong renderbuffertarget, GC::Root<WebGLRenderbuffer> renderbuffer)
{
    m_context->make_current();

    auto renderbuffer_handle = 0;
    if (renderbuffer) {
        auto handle_or_error = renderbuffer->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return ;
        }
        renderbuffer_handle = handle_or_error.release_value();
    }
    glFramebufferRenderbuffer(target, attachment, renderbuffertarget, renderbuffer_handle);
}

void WebGL2RenderingContextImpl::framebuffer_texture2d(WebIDL::UnsignedLong target, WebIDL::UnsignedLong attachment, WebIDL::UnsignedLong textarget, GC::Root<WebGLTexture> texture, WebIDL::Long level)
{
    m_context->make_current();

    auto texture_handle = 0;
    if (texture) {
        auto handle_or_error = texture->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return ;
        }
        texture_handle = handle_or_error.release_value();
    }
    glFramebufferTexture2D(target, attachment, textarget, texture_handle, level);
}

void WebGL2RenderingContextImpl::front_face(WebIDL::UnsignedLong mode)
{
    m_context->make_current();
    glFrontFace(mode);
}

void WebGL2RenderingContextImpl::generate_mipmap(WebIDL::UnsignedLong target)
{
    m_context->make_current();
    glGenerateMipmap(target);
}

GC::Root<WebGLActiveInfo> WebGL2RenderingContextImpl::get_active_attrib(GC::Root<WebGLProgram> program, WebIDL::UnsignedLong index)
{
    m_context->make_current();

    GLuint program_handle = 0;
    if (program) {
        auto handle_or_error = program->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return {};
        }
        program_handle = handle_or_error.release_value();
    }

    GLint size = 0;
    GLenum type = 0;
    GLsizei buf_size = 256;
    GLsizei length = 0;
    GLchar name[256];
    glGetActiveAttrib(program_handle, index, buf_size, &length, &size, &type, name);
    auto readonly_bytes = ReadonlyBytes { name, static_cast<size_t>(length) };
    return WebGLActiveInfo::create(m_realm, String::from_utf8_without_validation(readonly_bytes), type, size);
}

GC::Root<WebGLActiveInfo> WebGL2RenderingContextImpl::get_active_uniform(GC::Root<WebGLProgram> program, WebIDL::UnsignedLong index)
{
    m_context->make_current();

    GLuint program_handle = 0;
    if (program) {
        auto handle_or_error = program->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return {};
        }
        program_handle = handle_or_error.release_value();
    }

    GLint size = 0;
    GLenum type = 0;
    GLsizei buf_size = 256;
    GLsizei length = 0;
    GLchar name[256];
    glGetActiveUniform(program_handle, index, buf_size, &length, &size, &type, name);
    auto readonly_bytes = ReadonlyBytes { name, static_cast<size_t>(length) };
    return WebGLActiveInfo::create(m_realm, String::from_utf8_without_validation(readonly_bytes), type, size);
}

WebIDL::Long WebGL2RenderingContextImpl::get_attrib_location(GC::Root<WebGLProgram> program, String name)
{
    m_context->make_current();

    auto program_handle = 0;
    if (program) {
        auto handle_or_error = program->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return -1;
        }
        program_handle = handle_or_error.release_value();
    }

    auto name_null_terminated = null_terminated_string(name);
    return glGetAttribLocation(program_handle, name_null_terminated.data());
}

JS::Value WebGL2RenderingContextImpl::get_buffer_parameter(WebIDL::UnsignedLong target, WebIDL::UnsignedLong pname)
{
    m_context->make_current();
    switch (pname) {
    case GL_BUFFER_SIZE: {
        GLint result;
        glGetBufferParameteriv(target, GL_BUFFER_SIZE, &result);
        return JS::Value(result);
    }

    case GL_BUFFER_USAGE: {
        GLint result;
        glGetBufferParameteriv(target, GL_BUFFER_USAGE, &result);
        return JS::Value(result);
    }

    default:
        dbgln("Unknown WebGL buffer parameter name: {:x}", pname);
        set_error(GL_INVALID_ENUM);
        return JS::js_null();
    }
}

JS::Value WebGL2RenderingContextImpl::get_parameter(WebIDL::UnsignedLong pname)
{
    m_context->make_current();
    switch (pname) {
    case GL_ACTIVE_TEXTURE: {
        GLint result;
        glGetIntegerv(GL_ACTIVE_TEXTURE, &result);
        return JS::Value(result);
    }
    case GL_ALIASED_LINE_WIDTH_RANGE: {
        Array<GLfloat, 2> result;
        glGetFloatv(GL_ALIASED_LINE_WIDTH_RANGE, result.data());
        auto byte_buffer = MUST(ByteBuffer::copy(result.data(), 2 * sizeof(GLfloat)));
        auto array_buffer = JS::ArrayBuffer::create(m_realm, move(byte_buffer));
        return JS::Float32Array::create(m_realm, 2, array_buffer);
    }
    case GL_ALIASED_POINT_SIZE_RANGE: {
        Array<GLfloat, 2> result;
        glGetFloatv(GL_ALIASED_POINT_SIZE_RANGE, result.data());
        auto byte_buffer = MUST(ByteBuffer::copy(result.data(), 2 * sizeof(GLfloat)));
        auto array_buffer = JS::ArrayBuffer::create(m_realm, move(byte_buffer));
        return JS::Float32Array::create(m_realm, 2, array_buffer);
    }
    case GL_ALPHA_BITS: {
        GLint result;
        glGetIntegerv(GL_ALPHA_BITS, &result);
        return JS::Value(result);
    }
    case GL_ARRAY_BUFFER_BINDING: {
        GLint result;
        glGetIntegerv(GL_ARRAY_BUFFER_BINDING, &result);
        if (!result)
            return JS::js_null();
        return WebGLBuffer::create(m_realm, *this, result);
    }
    case GL_BLEND: {
        GLint result;
        glGetIntegerv(GL_BLEND, &result);
        return JS::Value(result);
    }
    case GL_BLEND_COLOR: {
        Array<GLfloat, 4> result;
        glGetFloatv(GL_BLEND_COLOR, result.data());
        auto byte_buffer = MUST(ByteBuffer::copy(result.data(), 4 * sizeof(GLfloat)));
        auto array_buffer = JS::ArrayBuffer::create(m_realm, move(byte_buffer));
        return JS::Float32Array::create(m_realm, 4, array_buffer);
    }
    case GL_BLEND_DST_ALPHA: {
        GLint result;
        glGetIntegerv(GL_BLEND_DST_ALPHA, &result);
        return JS::Value(result);
    }
    case GL_BLEND_DST_RGB: {
        GLint result;
        glGetIntegerv(GL_BLEND_DST_RGB, &result);
        return JS::Value(result);
    }
    case GL_BLEND_EQUATION_ALPHA: {
        GLint result;
        glGetIntegerv(GL_BLEND_EQUATION_ALPHA, &result);
        return JS::Value(result);
    }
    case GL_BLEND_EQUATION_RGB: {
        GLint result;
        glGetIntegerv(GL_BLEND_EQUATION_RGB, &result);
        return JS::Value(result);
    }
    case GL_BLEND_SRC_ALPHA: {
        GLint result;
        glGetIntegerv(GL_BLEND_SRC_ALPHA, &result);
        return JS::Value(result);
    }
    case GL_BLEND_SRC_RGB: {
        GLint result;
        glGetIntegerv(GL_BLEND_SRC_RGB, &result);
        return JS::Value(result);
    }
    case GL_BLUE_BITS: {
        GLint result;
        glGetIntegerv(GL_BLUE_BITS, &result);
        return JS::Value(result);
    }
    case GL_COLOR_CLEAR_VALUE: {
        Array<GLfloat, 4> result;
        glGetFloatv(GL_COLOR_CLEAR_VALUE, result.data());
        auto byte_buffer = MUST(ByteBuffer::copy(result.data(), 4 * sizeof(GLfloat)));
        auto array_buffer = JS::ArrayBuffer::create(m_realm, move(byte_buffer));
        return JS::Float32Array::create(m_realm, 4, array_buffer);
    }
    case GL_CULL_FACE: {
        GLint result;
        glGetIntegerv(GL_CULL_FACE, &result);
        return JS::Value(result);
    }
    case GL_CULL_FACE_MODE: {
        GLint result;
        glGetIntegerv(GL_CULL_FACE_MODE, &result);
        return JS::Value(result);
    }
    case GL_CURRENT_PROGRAM: {
        GLint result;
        glGetIntegerv(GL_CURRENT_PROGRAM, &result);
        if (!result)
            return JS::js_null();
        return WebGLProgram::create(m_realm, *this, result);
    }
    case GL_DEPTH_BITS: {
        GLint result;
        glGetIntegerv(GL_DEPTH_BITS, &result);
        return JS::Value(result);
    }
    case GL_DEPTH_CLEAR_VALUE: {
        GLint result;
        glGetIntegerv(GL_DEPTH_CLEAR_VALUE, &result);
        return JS::Value(result);
    }
    case GL_DEPTH_FUNC: {
        GLint result;
        glGetIntegerv(GL_DEPTH_FUNC, &result);
        return JS::Value(result);
    }
    case GL_DEPTH_RANGE: {
        Array<GLfloat, 2> result;
        glGetFloatv(GL_DEPTH_RANGE, result.data());
        auto byte_buffer = MUST(ByteBuffer::copy(result.data(), 2 * sizeof(GLfloat)));
        auto array_buffer = JS::ArrayBuffer::create(m_realm, move(byte_buffer));
        return JS::Float32Array::create(m_realm, 2, array_buffer);
    }
    case GL_DEPTH_TEST: {
        GLint result;
        glGetIntegerv(GL_DEPTH_TEST, &result);
        return JS::Value(result);
    }
    case GL_DEPTH_WRITEMASK: {
        GLint result;
        glGetIntegerv(GL_DEPTH_WRITEMASK, &result);
        return JS::Value(result);
    }
    case GL_DITHER: {
        GLint result;
        glGetIntegerv(GL_DITHER, &result);
        return JS::Value(result);
    }
    case GL_ELEMENT_ARRAY_BUFFER_BINDING: {
        GLint result;
        glGetIntegerv(GL_ELEMENT_ARRAY_BUFFER_BINDING, &result);
        if (!result)
            return JS::js_null();
        return WebGLBuffer::create(m_realm, *this, result);
    }
    case GL_FRAMEBUFFER_BINDING: {
        GLint result;
        glGetIntegerv(GL_FRAMEBUFFER_BINDING, &result);
        if (!result)
            return JS::js_null();
        return WebGLFramebuffer::create(m_realm, *this, result);
    }
    case GL_FRONT_FACE: {
        GLint result;
        glGetIntegerv(GL_FRONT_FACE, &result);
        return JS::Value(result);
    }
    case GL_GENERATE_MIPMAP_HINT: {
        GLint result;
        glGetIntegerv(GL_GENERATE_MIPMAP_HINT, &result);
        return JS::Value(result);
    }
    case GL_GREEN_BITS: {
        GLint result;
        glGetIntegerv(GL_GREEN_BITS, &result);
        return JS::Value(result);
    }
    case GL_IMPLEMENTATION_COLOR_READ_FORMAT: {
        GLint result;
        glGetIntegerv(GL_IMPLEMENTATION_COLOR_READ_FORMAT, &result);
        return JS::Value(result);
    }
    case GL_IMPLEMENTATION_COLOR_READ_TYPE: {
        GLint result;
        glGetIntegerv(GL_IMPLEMENTATION_COLOR_READ_TYPE, &result);
        return JS::Value(result);
    }
    case GL_LINE_WIDTH: {
        GLint result;
        glGetIntegerv(GL_LINE_WIDTH, &result);
        return JS::Value(result);
    }
    case GL_MAX_COMBINED_TEXTURE_IMAGE_UNITS: {
        GLint result;
        glGetIntegerv(GL_MAX_COMBINED_TEXTURE_IMAGE_UNITS, &result);
        return JS::Value(result);
    }
    case GL_MAX_CUBE_MAP_TEXTURE_SIZE: {
        GLint result;
        glGetIntegerv(GL_MAX_CUBE_MAP_TEXTURE_SIZE, &result);
        return JS::Value(result);
    }
    case GL_MAX_FRAGMENT_UNIFORM_VECTORS: {
        GLint result;
        glGetIntegerv(GL_MAX_FRAGMENT_UNIFORM_VECTORS, &result);
        return JS::Value(result);
    }
    case GL_MAX_RENDERBUFFER_SIZE: {
        GLint result;
        glGetIntegerv(GL_MAX_RENDERBUFFER_SIZE, &result);
        return JS::Value(result);
    }
    case GL_MAX_TEXTURE_IMAGE_UNITS: {
        GLint result;
        glGetIntegerv(GL_MAX_TEXTURE_IMAGE_UNITS, &result);
        return JS::Value(result);
    }
    case GL_MAX_TEXTURE_SIZE: {
        GLint result;
        glGetIntegerv(GL_MAX_TEXTURE_SIZE, &result);
        return JS::Value(result);
    }
    case GL_MAX_VARYING_VECTORS: {
        GLint result;
        glGetIntegerv(GL_MAX_VARYING_VECTORS, &result);
        return JS::Value(result);
    }
    case GL_MAX_VERTEX_ATTRIBS: {
        GLint result;
        glGetIntegerv(GL_MAX_VERTEX_ATTRIBS, &result);
        return JS::Value(result);
    }
    case GL_MAX_VERTEX_TEXTURE_IMAGE_UNITS: {
        GLint result;
        glGetIntegerv(GL_MAX_VERTEX_TEXTURE_IMAGE_UNITS, &result);
        return JS::Value(result);
    }
    case GL_MAX_VERTEX_UNIFORM_VECTORS: {
        GLint result;
        glGetIntegerv(GL_MAX_VERTEX_UNIFORM_VECTORS, &result);
        return JS::Value(result);
    }
    case GL_MAX_VIEWPORT_DIMS: {
        Array<GLint, 2> result;
        glGetIntegerv(GL_MAX_VIEWPORT_DIMS, result.data());
        auto byte_buffer = MUST(ByteBuffer::copy(result.data(), 2 * sizeof(GLint)));
        auto array_buffer = JS::ArrayBuffer::create(m_realm, move(byte_buffer));
        return JS::Int32Array::create(m_realm, 2, array_buffer);
    }
    case GL_PACK_ALIGNMENT: {
        GLint result;
        glGetIntegerv(GL_PACK_ALIGNMENT, &result);
        return JS::Value(result);
    }
    case GL_POLYGON_OFFSET_FACTOR: {
        GLint result;
        glGetIntegerv(GL_POLYGON_OFFSET_FACTOR, &result);
        return JS::Value(result);
    }
    case GL_POLYGON_OFFSET_FILL: {
        GLint result;
        glGetIntegerv(GL_POLYGON_OFFSET_FILL, &result);
        return JS::Value(result);
    }
    case GL_POLYGON_OFFSET_UNITS: {
        GLint result;
        glGetIntegerv(GL_POLYGON_OFFSET_UNITS, &result);
        return JS::Value(result);
    }
    case GL_RED_BITS: {
        GLint result;
        glGetIntegerv(GL_RED_BITS, &result);
        return JS::Value(result);
    }
    case GL_RENDERBUFFER_BINDING: {
        GLint result;
        glGetIntegerv(GL_RENDERBUFFER_BINDING, &result);
        if (!result)
            return JS::js_null();
        return WebGLRenderbuffer::create(m_realm, *this, result);
    }
    case GL_RENDERER: {
        auto result = reinterpret_cast<const char*>(glGetString(GL_RENDERER));
        return JS::PrimitiveString::create(m_realm->vm(), ByteString { result });    }
    case GL_SAMPLE_ALPHA_TO_COVERAGE: {
        GLint result;
        glGetIntegerv(GL_SAMPLE_ALPHA_TO_COVERAGE, &result);
        return JS::Value(result);
    }
    case GL_SAMPLE_BUFFERS: {
        GLint result;
        glGetIntegerv(GL_SAMPLE_BUFFERS, &result);
        return JS::Value(result);
    }
    case GL_SAMPLE_COVERAGE: {
        GLint result;
        glGetIntegerv(GL_SAMPLE_COVERAGE, &result);
        return JS::Value(result);
    }
    case GL_SAMPLE_COVERAGE_INVERT: {
        GLint result;
        glGetIntegerv(GL_SAMPLE_COVERAGE_INVERT, &result);
        return JS::Value(result);
    }
    case GL_SAMPLE_COVERAGE_VALUE: {
        GLint result;
        glGetIntegerv(GL_SAMPLE_COVERAGE_VALUE, &result);
        return JS::Value(result);
    }
    case GL_SAMPLES: {
        GLint result;
        glGetIntegerv(GL_SAMPLES, &result);
        return JS::Value(result);
    }
    case GL_SCISSOR_BOX: {
        Array<GLint, 4> result;
        glGetIntegerv(GL_SCISSOR_BOX, result.data());
        auto byte_buffer = MUST(ByteBuffer::copy(result.data(), 4 * sizeof(GLint)));
        auto array_buffer = JS::ArrayBuffer::create(m_realm, move(byte_buffer));
        return JS::Int32Array::create(m_realm, 4, array_buffer);
    }
    case GL_SCISSOR_TEST: {
        GLint result;
        glGetIntegerv(GL_SCISSOR_TEST, &result);
        return JS::Value(result);
    }
    case GL_SHADING_LANGUAGE_VERSION: {
        auto result = reinterpret_cast<const char*>(glGetString(GL_SHADING_LANGUAGE_VERSION));
        return JS::PrimitiveString::create(m_realm->vm(), ByteString { result });    }
    case GL_STENCIL_BACK_FAIL: {
        GLint result;
        glGetIntegerv(GL_STENCIL_BACK_FAIL, &result);
        return JS::Value(result);
    }
    case GL_STENCIL_BACK_FUNC: {
        GLint result;
        glGetIntegerv(GL_STENCIL_BACK_FUNC, &result);
        return JS::Value(result);
    }
    case GL_STENCIL_BACK_PASS_DEPTH_FAIL: {
        GLint result;
        glGetIntegerv(GL_STENCIL_BACK_PASS_DEPTH_FAIL, &result);
        return JS::Value(result);
    }
    case GL_STENCIL_BACK_PASS_DEPTH_PASS: {
        GLint result;
        glGetIntegerv(GL_STENCIL_BACK_PASS_DEPTH_PASS, &result);
        return JS::Value(result);
    }
    case GL_STENCIL_BACK_REF: {
        GLint result;
        glGetIntegerv(GL_STENCIL_BACK_REF, &result);
        return JS::Value(result);
    }
    case GL_STENCIL_BACK_VALUE_MASK: {
        GLint result;
        glGetIntegerv(GL_STENCIL_BACK_VALUE_MASK, &result);
        return JS::Value(result);
    }
    case GL_STENCIL_BACK_WRITEMASK: {
        GLint result;
        glGetIntegerv(GL_STENCIL_BACK_WRITEMASK, &result);
        return JS::Value(result);
    }
    case GL_STENCIL_BITS: {
        GLint result;
        glGetIntegerv(GL_STENCIL_BITS, &result);
        return JS::Value(result);
    }
    case GL_STENCIL_CLEAR_VALUE: {
        GLint result;
        glGetIntegerv(GL_STENCIL_CLEAR_VALUE, &result);
        return JS::Value(result);
    }
    case GL_STENCIL_FAIL: {
        GLint result;
        glGetIntegerv(GL_STENCIL_FAIL, &result);
        return JS::Value(result);
    }
    case GL_STENCIL_FUNC: {
        GLint result;
        glGetIntegerv(GL_STENCIL_FUNC, &result);
        return JS::Value(result);
    }
    case GL_STENCIL_PASS_DEPTH_FAIL: {
        GLint result;
        glGetIntegerv(GL_STENCIL_PASS_DEPTH_FAIL, &result);
        return JS::Value(result);
    }
    case GL_STENCIL_PASS_DEPTH_PASS: {
        GLint result;
        glGetIntegerv(GL_STENCIL_PASS_DEPTH_PASS, &result);
        return JS::Value(result);
    }
    case GL_STENCIL_REF: {
        GLint result;
        glGetIntegerv(GL_STENCIL_REF, &result);
        return JS::Value(result);
    }
    case GL_STENCIL_TEST: {
        GLint result;
        glGetIntegerv(GL_STENCIL_TEST, &result);
        return JS::Value(result);
    }
    case GL_STENCIL_VALUE_MASK: {
        GLint result;
        glGetIntegerv(GL_STENCIL_VALUE_MASK, &result);
        return JS::Value(result);
    }
    case GL_STENCIL_WRITEMASK: {
        GLint result;
        glGetIntegerv(GL_STENCIL_WRITEMASK, &result);
        return JS::Value(result);
    }
    case GL_SUBPIXEL_BITS: {
        GLint result;
        glGetIntegerv(GL_SUBPIXEL_BITS, &result);
        return JS::Value(result);
    }
    case GL_TEXTURE_BINDING_2D: {
        GLint result;
        glGetIntegerv(GL_TEXTURE_BINDING_2D, &result);
        if (!result)
            return JS::js_null();
        return WebGLTexture::create(m_realm, *this, result);
    }
    case GL_TEXTURE_BINDING_CUBE_MAP: {
        GLint result;
        glGetIntegerv(GL_TEXTURE_BINDING_CUBE_MAP, &result);
        if (!result)
            return JS::js_null();
        return WebGLTexture::create(m_realm, *this, result);
    }
    case GL_UNPACK_ALIGNMENT: {
        GLint result;
        glGetIntegerv(GL_UNPACK_ALIGNMENT, &result);
        return JS::Value(result);
    }
    case GL_VENDOR: {
        auto result = reinterpret_cast<const char*>(glGetString(GL_VENDOR));
        return JS::PrimitiveString::create(m_realm->vm(), ByteString { result });    }
    case GL_VERSION: {
        auto result = reinterpret_cast<const char*>(glGetString(GL_VERSION));
        return JS::PrimitiveString::create(m_realm->vm(), ByteString { result });    }
    case GL_VIEWPORT: {
        Array<GLint, 4> result;
        glGetIntegerv(GL_VIEWPORT, result.data());
        auto byte_buffer = MUST(ByteBuffer::copy(result.data(), 4 * sizeof(GLint)));
        auto array_buffer = JS::ArrayBuffer::create(m_realm, move(byte_buffer));
        return JS::Int32Array::create(m_realm, 4, array_buffer);
    }
    case GL_MAX_SAMPLES: {
        GLint result;
        glGetIntegerv(GL_MAX_SAMPLES, &result);
        return JS::Value(result);
    }
    case GL_MAX_3D_TEXTURE_SIZE: {
        GLint result;
        glGetIntegerv(GL_MAX_3D_TEXTURE_SIZE, &result);
        return JS::Value(result);
    }
    case GL_MAX_ARRAY_TEXTURE_LAYERS: {
        GLint result;
        glGetIntegerv(GL_MAX_ARRAY_TEXTURE_LAYERS, &result);
        return JS::Value(result);
    }
    case GL_MAX_COLOR_ATTACHMENTS: {
        GLint result;
        glGetIntegerv(GL_MAX_COLOR_ATTACHMENTS, &result);
        return JS::Value(result);
    }
    case GL_MAX_VERTEX_UNIFORM_COMPONENTS: {
        GLint result;
        glGetIntegerv(GL_MAX_VERTEX_UNIFORM_COMPONENTS, &result);
        return JS::Value(result);
    }
    case GL_MAX_UNIFORM_BLOCK_SIZE: {
        GLint64 result;
        glGetInteger64v(GL_MAX_UNIFORM_BLOCK_SIZE, &result);
        return JS::Value(static_cast<double>(result));
    }
    case GL_MAX_UNIFORM_BUFFER_BINDINGS: {
        GLint result;
        glGetIntegerv(GL_MAX_UNIFORM_BUFFER_BINDINGS, &result);
        return JS::Value(result);
    }
    case GL_UNIFORM_BUFFER_OFFSET_ALIGNMENT: {
        GLint result;
        glGetIntegerv(GL_UNIFORM_BUFFER_OFFSET_ALIGNMENT, &result);
        return JS::Value(result);
    }
    case GL_MAX_DRAW_BUFFERS: {
        GLint result;
        glGetIntegerv(GL_MAX_DRAW_BUFFERS, &result);
        return JS::Value(result);
    }
    case GL_MAX_VERTEX_UNIFORM_BLOCKS: {
        GLint result;
        glGetIntegerv(GL_MAX_VERTEX_UNIFORM_BLOCKS, &result);
        return JS::Value(result);
    }
    case GL_MAX_FRAGMENT_INPUT_COMPONENTS: {
        GLint result;
        glGetIntegerv(GL_MAX_FRAGMENT_INPUT_COMPONENTS, &result);
        return JS::Value(result);
    }
    case GL_MAX_COMBINED_UNIFORM_BLOCKS: {
        GLint result;
        glGetIntegerv(GL_MAX_COMBINED_UNIFORM_BLOCKS, &result);
        return JS::Value(result);
    }
    default:
        dbgln("Unknown WebGL parameter name: {:x}", pname);
        set_error(GL_INVALID_ENUM);
        return JS::js_null();
    }
}

WebIDL::UnsignedLong WebGL2RenderingContextImpl::get_error()
{
    m_context->make_current();
    return glGetError();
}

JS::Value WebGL2RenderingContextImpl::get_program_parameter(GC::Root<WebGLProgram> program, WebIDL::UnsignedLong pname)
{
    m_context->make_current();

    GLuint program_handle = 0;
    if (program) {
        auto handle_or_error = program->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return JS::js_null();
        }
        program_handle = handle_or_error.release_value();
    }

    GLint result = 0;
    glGetProgramiv(program_handle, pname, &result);
    return JS::Value(result);
}

Optional<String> WebGL2RenderingContextImpl::get_program_info_log(GC::Root<WebGLProgram> program)
{
    m_context->make_current();

    GLuint program_handle = 0;
    if (program) {
        auto handle_or_error = program->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return {};
        }
        program_handle = handle_or_error.release_value();
    }

    GLint info_log_length = 0;
    glGetProgramiv(program_handle, GL_INFO_LOG_LENGTH, &info_log_length);
    Vector<GLchar> info_log;
    info_log.resize(info_log_length);
    if (!info_log_length)
        return String {};
    glGetProgramInfoLog(program_handle, info_log_length, nullptr, info_log.data());
    return String::from_utf8_without_validation(ReadonlyBytes { info_log.data(), static_cast<size_t>(info_log_length - 1) });
}

JS::Value WebGL2RenderingContextImpl::get_shader_parameter(GC::Root<WebGLShader> shader, WebIDL::UnsignedLong pname)
{
    m_context->make_current();

    GLuint shader_handle = 0;
    if (shader) {
        auto handle_or_error = shader->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return JS::js_null();
        }
        shader_handle = handle_or_error.release_value();
    }

    GLint result = 0;
    glGetShaderiv(shader_handle, pname, &result);
    return JS::Value(result);
}

GC::Root<WebGLShaderPrecisionFormat> WebGL2RenderingContextImpl::get_shader_precision_format(WebIDL::UnsignedLong shadertype, WebIDL::UnsignedLong precisiontype)
{
    m_context->make_current();

    GLint range[2];
    GLint precision;
    glGetShaderPrecisionFormat(shadertype, precisiontype, range, &precision);
    return WebGLShaderPrecisionFormat::create(m_realm, range[0], range[1], precision);
}

Optional<String> WebGL2RenderingContextImpl::get_shader_info_log(GC::Root<WebGLShader> shader)
{
    m_context->make_current();

    GLuint shader_handle = 0;
    if (shader) {
        auto handle_or_error = shader->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return {};
        }
        shader_handle = handle_or_error.release_value();
    }

    GLint info_log_length = 0;
    glGetShaderiv(shader_handle, GL_INFO_LOG_LENGTH, &info_log_length);
    Vector<GLchar> info_log;
    info_log.resize(info_log_length);
    if (!info_log_length)
        return String {};
    glGetShaderInfoLog(shader_handle, info_log_length, nullptr, info_log.data());
    return String::from_utf8_without_validation(ReadonlyBytes { info_log.data(), static_cast<size_t>(info_log_length - 1) });
}

GC::Root<WebGLUniformLocation> WebGL2RenderingContextImpl::get_uniform_location(GC::Root<WebGLProgram> program, String name)
{
    m_context->make_current();

    GLuint program_handle = 0;
    if (program) {
        auto handle_or_error = program->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return {};
        }
        program_handle = handle_or_error.release_value();
    }

    auto name_null_terminated = null_terminated_string(name);
    return WebGLUniformLocation::create(m_realm, glGetUniformLocation(program_handle, name_null_terminated.data()));
}

void WebGL2RenderingContextImpl::hint(WebIDL::UnsignedLong target, WebIDL::UnsignedLong mode)
{
    m_context->make_current();
    glHint(target, mode);
}

bool WebGL2RenderingContextImpl::is_buffer(GC::Root<WebGLBuffer> buffer)
{
    m_context->make_current();

    auto buffer_handle = 0;
    if (buffer) {
        auto handle_or_error = buffer->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return false;
        }
        buffer_handle = handle_or_error.release_value();
    }
    return glIsBuffer(buffer_handle);
}

bool WebGL2RenderingContextImpl::is_enabled(WebIDL::UnsignedLong cap)
{
    m_context->make_current();
    return glIsEnabled(cap);
}

bool WebGL2RenderingContextImpl::is_framebuffer(GC::Root<WebGLFramebuffer> framebuffer)
{
    m_context->make_current();

    auto framebuffer_handle = 0;
    if (framebuffer) {
        auto handle_or_error = framebuffer->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return false;
        }
        framebuffer_handle = handle_or_error.release_value();
    }
    return glIsFramebuffer(framebuffer_handle);
}

bool WebGL2RenderingContextImpl::is_program(GC::Root<WebGLProgram> program)
{
    m_context->make_current();

    auto program_handle = 0;
    if (program) {
        auto handle_or_error = program->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return false;
        }
        program_handle = handle_or_error.release_value();
    }
    return glIsProgram(program_handle);
}

bool WebGL2RenderingContextImpl::is_renderbuffer(GC::Root<WebGLRenderbuffer> renderbuffer)
{
    m_context->make_current();

    auto renderbuffer_handle = 0;
    if (renderbuffer) {
        auto handle_or_error = renderbuffer->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return false;
        }
        renderbuffer_handle = handle_or_error.release_value();
    }
    return glIsRenderbuffer(renderbuffer_handle);
}

bool WebGL2RenderingContextImpl::is_shader(GC::Root<WebGLShader> shader)
{
    m_context->make_current();

    auto shader_handle = 0;
    if (shader) {
        auto handle_or_error = shader->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return false;
        }
        shader_handle = handle_or_error.release_value();
    }
    return glIsShader(shader_handle);
}

bool WebGL2RenderingContextImpl::is_texture(GC::Root<WebGLTexture> texture)
{
    m_context->make_current();

    auto texture_handle = 0;
    if (texture) {
        auto handle_or_error = texture->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return false;
        }
        texture_handle = handle_or_error.release_value();
    }
    return glIsTexture(texture_handle);
}

void WebGL2RenderingContextImpl::line_width(float width)
{
    m_context->make_current();
    glLineWidth(width);
}

void WebGL2RenderingContextImpl::link_program(GC::Root<WebGLProgram> program)
{
    m_context->make_current();

    auto program_handle = 0;
    if (program) {
        auto handle_or_error = program->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return ;
        }
        program_handle = handle_or_error.release_value();
    }
    glLinkProgram(program_handle);
}

void WebGL2RenderingContextImpl::pixel_storei(WebIDL::UnsignedLong pname, WebIDL::Long param)
{
    m_context->make_current();
    glPixelStorei(pname, param);
}

void WebGL2RenderingContextImpl::polygon_offset(float factor, float units)
{
    m_context->make_current();
    glPolygonOffset(factor, units);
}

void WebGL2RenderingContextImpl::renderbuffer_storage(WebIDL::UnsignedLong target, WebIDL::UnsignedLong internalformat, WebIDL::Long width, WebIDL::Long height)
{
    m_context->make_current();
    glRenderbufferStorage(target, internalformat, width, height);
}

void WebGL2RenderingContextImpl::sample_coverage(float value, bool invert)
{
    m_context->make_current();
    glSampleCoverage(value, invert);
}

void WebGL2RenderingContextImpl::scissor(WebIDL::Long x, WebIDL::Long y, WebIDL::Long width, WebIDL::Long height)
{
    m_context->make_current();
    glScissor(x, y, width, height);
}

void WebGL2RenderingContextImpl::shader_source(GC::Root<WebGLShader> shader, String source)
{
    m_context->make_current();

    GLuint shader_handle = 0;
    if (shader) {
        auto handle_or_error = shader->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return ;
        }
        shader_handle = handle_or_error.release_value();
    }

    Vector<GLchar*> strings;
    auto string = null_terminated_string(source);
    strings.append(string.data());
    Vector<GLint> length;
    length.append(source.bytes().size());
    glShaderSource(shader_handle, 1, strings.data(), length.data());
}

void WebGL2RenderingContextImpl::stencil_func(WebIDL::UnsignedLong func, WebIDL::Long ref, WebIDL::UnsignedLong mask)
{
    m_context->make_current();
    glStencilFunc(func, ref, mask);
}

void WebGL2RenderingContextImpl::stencil_func_separate(WebIDL::UnsignedLong face, WebIDL::UnsignedLong func, WebIDL::Long ref, WebIDL::UnsignedLong mask)
{
    m_context->make_current();
    glStencilFuncSeparate(face, func, ref, mask);
}

void WebGL2RenderingContextImpl::stencil_mask(WebIDL::UnsignedLong mask)
{
    m_context->make_current();
    glStencilMask(mask);
}

void WebGL2RenderingContextImpl::stencil_mask_separate(WebIDL::UnsignedLong face, WebIDL::UnsignedLong mask)
{
    m_context->make_current();
    glStencilMaskSeparate(face, mask);
}

void WebGL2RenderingContextImpl::stencil_op(WebIDL::UnsignedLong fail, WebIDL::UnsignedLong zfail, WebIDL::UnsignedLong zpass)
{
    m_context->make_current();
    glStencilOp(fail, zfail, zpass);
}

void WebGL2RenderingContextImpl::stencil_op_separate(WebIDL::UnsignedLong face, WebIDL::UnsignedLong fail, WebIDL::UnsignedLong zfail, WebIDL::UnsignedLong zpass)
{
    m_context->make_current();
    glStencilOpSeparate(face, fail, zfail, zpass);
}

void WebGL2RenderingContextImpl::tex_parameterf(WebIDL::UnsignedLong target, WebIDL::UnsignedLong pname, float param)
{
    m_context->make_current();
    glTexParameterf(target, pname, param);
}

void WebGL2RenderingContextImpl::tex_parameteri(WebIDL::UnsignedLong target, WebIDL::UnsignedLong pname, WebIDL::Long param)
{
    m_context->make_current();
    glTexParameteri(target, pname, param);
}

void WebGL2RenderingContextImpl::uniform1f(GC::Root<WebGLUniformLocation> location, float x)
{
    m_context->make_current();
    glUniform1f(location ? location->handle() : 0, x);
}

void WebGL2RenderingContextImpl::uniform2f(GC::Root<WebGLUniformLocation> location, float x, float y)
{
    m_context->make_current();
    glUniform2f(location ? location->handle() : 0, x, y);
}

void WebGL2RenderingContextImpl::uniform3f(GC::Root<WebGLUniformLocation> location, float x, float y, float z)
{
    m_context->make_current();
    glUniform3f(location ? location->handle() : 0, x, y, z);
}

void WebGL2RenderingContextImpl::uniform4f(GC::Root<WebGLUniformLocation> location, float x, float y, float z, float w)
{
    m_context->make_current();
    glUniform4f(location ? location->handle() : 0, x, y, z, w);
}

void WebGL2RenderingContextImpl::uniform1i(GC::Root<WebGLUniformLocation> location, WebIDL::Long x)
{
    m_context->make_current();
    glUniform1i(location ? location->handle() : 0, x);
}

void WebGL2RenderingContextImpl::uniform2i(GC::Root<WebGLUniformLocation> location, WebIDL::Long x, WebIDL::Long y)
{
    m_context->make_current();
    glUniform2i(location ? location->handle() : 0, x, y);
}

void WebGL2RenderingContextImpl::uniform3i(GC::Root<WebGLUniformLocation> location, WebIDL::Long x, WebIDL::Long y, WebIDL::Long z)
{
    m_context->make_current();
    glUniform3i(location ? location->handle() : 0, x, y, z);
}

void WebGL2RenderingContextImpl::uniform4i(GC::Root<WebGLUniformLocation> location, WebIDL::Long x, WebIDL::Long y, WebIDL::Long z, WebIDL::Long w)
{
    m_context->make_current();
    glUniform4i(location ? location->handle() : 0, x, y, z, w);
}

void WebGL2RenderingContextImpl::use_program(GC::Root<WebGLProgram> program)
{
    m_context->make_current();

    auto program_handle = 0;
    if (program) {
        auto handle_or_error = program->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return ;
        }
        program_handle = handle_or_error.release_value();
    }
    glUseProgram(program_handle);
}

void WebGL2RenderingContextImpl::validate_program(GC::Root<WebGLProgram> program)
{
    m_context->make_current();

    auto program_handle = 0;
    if (program) {
        auto handle_or_error = program->handle(this);
        if (handle_or_error.is_error()) {
            set_error(GL_INVALID_OPERATION);
            return ;
        }
        program_handle = handle_or_error.release_value();
    }
    glValidateProgram(program_handle);
}

void WebGL2RenderingContextImpl::vertex_attrib1f(WebIDL::UnsignedLong index, float x)
{
    m_context->make_current();
    glVertexAttrib1f(index, x);
}

void WebGL2RenderingContextImpl::vertex_attrib2f(WebIDL::UnsignedLong index, float x, float y)
{
    m_context->make_current();
    glVertexAttrib2f(index, x, y);
}

void WebGL2RenderingContextImpl::vertex_attrib3f(WebIDL::UnsignedLong index, float x, float y, float z)
{
    m_context->make_current();
    glVertexAttrib3f(index, x, y, z);
}

void WebGL2RenderingContextImpl::vertex_attrib4f(WebIDL::UnsignedLong index, float x, float y, float z, float w)
{
    m_context->make_current();
    glVertexAttrib4f(index, x, y, z, w);
}

void WebGL2RenderingContextImpl::vertex_attrib1fv(WebIDL::UnsignedLong index, Variant<GC::Root<WebIDL::BufferSource>, Vector<float>> values)
{
    m_context->make_current();

    if (values.has<Vector<float>>()) {
        auto& data = values.get<Vector<float>>();
        glVertexAttrib1fv(index, data.data());
        return;
    }

    auto& typed_array_base = static_cast<JS::TypedArrayBase&>(*values.get<GC::Root<WebIDL::BufferSource>>()->raw_object());
    auto& float32_array = verify_cast<JS::Float32Array>(typed_array_base);
    float const* data = float32_array.data().data();
    glVertexAttrib1fv(index, data);
}

void WebGL2RenderingContextImpl::vertex_attrib2fv(WebIDL::UnsignedLong index, Variant<GC::Root<WebIDL::BufferSource>, Vector<float>> values)
{
    m_context->make_current();

    if (values.has<Vector<float>>()) {
        auto& data = values.get<Vector<float>>();
        glVertexAttrib2fv(index, data.data());
        return;
    }

    auto& typed_array_base = static_cast<JS::TypedArrayBase&>(*values.get<GC::Root<WebIDL::BufferSource>>()->raw_object());
    auto& float32_array = verify_cast<JS::Float32Array>(typed_array_base);
    float const* data = float32_array.data().data();
    glVertexAttrib2fv(index, data);
}

void WebGL2RenderingContextImpl::vertex_attrib3fv(WebIDL::UnsignedLong index, Variant<GC::Root<WebIDL::BufferSource>, Vector<float>> values)
{
    m_context->make_current();

    if (values.has<Vector<float>>()) {
        auto& data = values.get<Vector<float>>();
        glVertexAttrib3fv(index, data.data());
        return;
    }

    auto& typed_array_base = static_cast<JS::TypedArrayBase&>(*values.get<GC::Root<WebIDL::BufferSource>>()->raw_object());
    auto& float32_array = verify_cast<JS::Float32Array>(typed_array_base);
    float const* data = float32_array.data().data();
    glVertexAttrib3fv(index, data);
}

void WebGL2RenderingContextImpl::vertex_attrib4fv(WebIDL::UnsignedLong index, Variant<GC::Root<WebIDL::BufferSource>, Vector<float>> values)
{
    m_context->make_current();

    if (values.has<Vector<float>>()) {
        auto& data = values.get<Vector<float>>();
        glVertexAttrib4fv(index, data.data());
        return;
    }

    auto& typed_array_base = static_cast<JS::TypedArrayBase&>(*values.get<GC::Root<WebIDL::BufferSource>>()->raw_object());
    auto& float32_array = verify_cast<JS::Float32Array>(typed_array_base);
    float const* data = float32_array.data().data();
    glVertexAttrib4fv(index, data);
}

void WebGL2RenderingContextImpl::vertex_attrib_pointer(WebIDL::UnsignedLong index, WebIDL::Long size, WebIDL::UnsignedLong type, bool normalized, WebIDL::Long stride, WebIDL::LongLong offset)
{
    m_context->make_current();

    glVertexAttribPointer(index, size, type, normalized, stride, reinterpret_cast<void*>(offset));
}

void WebGL2RenderingContextImpl::viewport(WebIDL::Long x, WebIDL::Long y, WebIDL::Long width, WebIDL::Long height)
{
    m_context->make_current();
    glViewport(x, y, width, height);
}

}
