/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __FRAG_DETECT_SKEL_H__
#define __FRAG_DETECT_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct frag_detect {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *rodata;
	} maps;
	struct {
		struct bpf_program *frag_detect;
	} progs;
	struct {
		struct bpf_link *frag_detect;
	} links;

#ifdef __cplusplus
	static inline struct frag_detect *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct frag_detect *open_and_load();
	static inline int load(struct frag_detect *skel);
	static inline int attach(struct frag_detect *skel);
	static inline void detach(struct frag_detect *skel);
	static inline void destroy(struct frag_detect *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
frag_detect__destroy(struct frag_detect *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
frag_detect__create_skeleton(struct frag_detect *obj);

static inline struct frag_detect *
frag_detect__open_opts(const struct bpf_object_open_opts *opts)
{
	struct frag_detect *obj;
	int err;

	obj = (struct frag_detect *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = frag_detect__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	frag_detect__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct frag_detect *
frag_detect__open(void)
{
	return frag_detect__open_opts(NULL);
}

static inline int
frag_detect__load(struct frag_detect *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct frag_detect *
frag_detect__open_and_load(void)
{
	struct frag_detect *obj;
	int err;

	obj = frag_detect__open();
	if (!obj)
		return NULL;
	err = frag_detect__load(obj);
	if (err) {
		frag_detect__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
frag_detect__attach(struct frag_detect *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
frag_detect__detach(struct frag_detect *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *frag_detect__elf_bytes(size_t *sz);

static inline int
frag_detect__create_skeleton(struct frag_detect *obj)
{
	struct bpf_object_skeleton *s;
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "frag_detect";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 1;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	s->maps[0].name = "frag_det.rodata";
	s->maps[0].map = &obj->maps.rodata;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "frag_detect";
	s->progs[0].prog = &obj->progs.frag_detect;
	s->progs[0].link = &obj->links.frag_detect;

	s->data = frag_detect__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *frag_detect__elf_bytes(size_t *sz)
{
	static const char data[] __attribute__((__aligned__(8))) = "\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x80\x02\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x09\0\
\x01\0\x61\x12\x50\0\0\0\0\0\x61\x14\x4c\0\0\0\0\0\xbf\x41\0\0\0\0\0\0\x07\x01\
\0\0\x0e\0\0\0\x2d\x21\x12\0\0\0\0\0\x71\x41\x0d\0\0\0\0\0\x67\x01\0\0\x08\0\0\
\0\x71\x43\x0c\0\0\0\0\0\x4f\x31\0\0\0\0\0\0\x55\x01\x0d\0\x08\0\0\0\xbf\x41\0\
\0\0\0\0\0\x07\x01\0\0\x22\0\0\0\x2d\x21\x0a\0\0\0\0\0\x69\x41\x14\0\0\0\0\0\
\x57\x01\0\0\x3f\xff\0\0\x15\x01\x07\0\0\0\0\0\xbf\x43\0\0\0\0\0\0\x07\x03\0\0\
\x1a\0\0\0\x07\x04\0\0\x1e\0\0\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x02\0\
\0\x31\0\0\0\x85\0\0\0\x06\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x49\x50\
\x76\x34\x20\x46\x72\x61\x67\x6d\x65\x6e\x74\x61\x74\x69\x6f\x6e\x20\x64\x65\
\x74\x65\x63\x74\x65\x64\x3a\x20\x73\x72\x63\x3d\x25\x70\x49\x34\x2c\x20\x64\
\x73\x74\x3d\x25\x70\x49\x34\x0a\0\x47\x50\x4c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x4d\0\0\0\x04\0\xf1\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x78\0\0\0\0\0\x03\0\xb8\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\0\0\x01\0\x05\0\
\0\0\0\0\0\0\0\0\x31\0\0\0\0\0\0\0\0\0\0\0\x03\0\x05\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x1b\0\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\xc8\0\0\0\0\0\0\0\x44\0\0\0\x11\
\0\x06\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\x98\0\0\0\0\0\0\0\x01\0\0\0\x04\0\0\
\0\x05\x03\x06\0\x2e\x74\x65\x78\x74\0\x66\x72\x61\x67\x5f\x64\x65\x74\x65\x63\
\x74\x2e\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x66\x72\x61\x67\x5f\x64\x65\x74\x65\x63\
\x74\0\x2e\x72\x65\x6c\x63\x6c\x61\x73\x73\x69\x66\x69\x65\x72\0\x2e\x6c\x6c\
\x76\x6d\x5f\x61\x64\x64\x72\x73\x69\x67\0\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\
\x66\x72\x61\x67\x5f\x64\x65\x74\x65\x63\x74\x5f\x6b\x65\x72\x6e\x2e\x63\0\x2e\
\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\x74\x61\x62\0\x2e\x72\x6f\x64\x61\
\x74\x61\0\x4c\x42\x42\x30\x5f\x35\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x60\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xfb\
\x01\0\0\0\0\0\0\x7f\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x01\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x2b\0\0\0\
\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\xc8\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x27\0\0\0\x09\0\0\0\x40\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe8\x01\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x08\0\0\0\
\x03\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x70\0\0\0\x01\0\0\0\x02\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x08\x01\0\0\0\0\0\0\x31\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x45\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x39\x01\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x36\0\0\0\x03\x4c\xff\x6f\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\
\0\xf8\x01\0\0\0\0\0\0\x03\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x68\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\x01\0\0\
\0\0\0\0\xa8\0\0\0\0\0\0\0\x01\0\0\0\x05\0\0\0\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\
\0\0";

	*sz = sizeof(data) - 1;
	return (const void *)data;
}

#ifdef __cplusplus
struct frag_detect *frag_detect::open(const struct bpf_object_open_opts *opts) { return frag_detect__open_opts(opts); }
struct frag_detect *frag_detect::open_and_load() { return frag_detect__open_and_load(); }
int frag_detect::load(struct frag_detect *skel) { return frag_detect__load(skel); }
int frag_detect::attach(struct frag_detect *skel) { return frag_detect__attach(skel); }
void frag_detect::detach(struct frag_detect *skel) { frag_detect__detach(skel); }
void frag_detect::destroy(struct frag_detect *skel) { frag_detect__destroy(skel); }
const void *frag_detect::elf_bytes(size_t *sz) { return frag_detect__elf_bytes(sz); }
#endif /* __cplusplus */


#endif /* __FRAG_DETECT_SKEL_H__ */
