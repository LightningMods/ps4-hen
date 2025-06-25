#include <stddef.h>
#include <stdint.h>

#include "sections.h"
#include "sparse.h"
#include "offsets.h"
#include "freebsd_helper.h"
#include "amd_helper.h"

extern uint16_t fw_version PAYLOAD_BSS;
extern const struct kpayload_offsets *fw_offsets PAYLOAD_BSS;

extern int (*proc_rwmem)(struct proc *p, struct uio *uio) PAYLOAD_BSS;
extern struct vmspace *(*vmspace_acquire_ref)(struct proc *p) PAYLOAD_BSS;
extern void (*vmspace_free)(struct vmspace *vm) PAYLOAD_BSS;
extern void (*vm_map_lock_read)(struct vm_map *map) PAYLOAD_BSS;
extern void (*vm_map_unlock_read)(struct vm_map *map) PAYLOAD_BSS;
extern int (*vm_map_lookup_entry)(struct vm_map *map, uint64_t address, struct vm_map_entry **entries) PAYLOAD_BSS;

extern size_t (*strlen)(const char *str) PAYLOAD_BSS;
extern void *(*malloc)(unsigned long size, void *type, int flags) PAYLOAD_BSS;
extern void (*free)(void *addr, void *type) PAYLOAD_BSS;
extern void *(*memcpy)(void *dst, const void *src, size_t len) PAYLOAD_BSS;
extern void *(*memset)(void *s, int c, size_t n) PAYLOAD_BSS;
extern int (*memcmp)(const void *ptr1, const void *ptr2, size_t num) PAYLOAD_BSS;
// Varies per FW
extern void (*eventhandler_register_old)(void *list, const char *name, void *func, void *arg, int priority) PAYLOAD_BSS; // < 5.50
extern void (*eventhandler_register)(void *list, const char *name, void *func, void *key, void *arg, int priority) PAYLOAD_BSS; // 5.50+ (Any changes after 6.72?)

extern void *M_TEMP PAYLOAD_BSS;
extern struct proc **ALLPROC PAYLOAD_BSS;

PAYLOAD_CODE static inline void *alloc(uint32_t size) {
  return malloc(size, M_TEMP, 2);
}

PAYLOAD_CODE static inline void dealloc(void *addr) {
  free(addr, M_TEMP);
}

PAYLOAD_CODE static struct proc *proc_find_by_name(const char *name) {
  struct proc *p;

  if (!name) {
    return NULL;
  }

  p = *ALLPROC;

  do {
    if (!memcmp(p->p_comm, name, strlen(name))) {
      return p;
    }
  } while ((p = p->p_forw));

  return NULL;
}

PAYLOAD_CODE static int proc_get_vm_map(struct proc *p, struct proc_vm_map_entry **entries, size_t *num_entries) {
  struct proc_vm_map_entry *info = NULL;
  struct vm_map_entry *entry = NULL;

  struct vmspace *vm = vmspace_acquire_ref(p);
  if (!vm) {
    return -1;
  }

  struct vm_map *map = &vm->vm_map;

  int num = map->nentries;
  if (!num) {
    vmspace_free(vm);
    return 0;
  }

  vm_map_lock_read(map);

  if (vm_map_lookup_entry(map, 0, &entry)) {
    vm_map_unlock_read(map);
    vmspace_free(vm);
    return -1;
  }

  info = (struct proc_vm_map_entry *)alloc(num * sizeof(struct proc_vm_map_entry));
  if (!info) {
    vm_map_unlock_read(map);
    vmspace_free(vm);
    return -1;
  }

  for (int i = 0; i < num; i++) {
    info[i].start = entry->start;
    info[i].end = entry->end;
    info[i].offset = entry->offset;
    info[i].prot = entry->prot & (entry->prot >> 8);
    memcpy(info[i].name, entry->name, sizeof(info[i].name));

    if (!(entry = entry->next)) {
      break;
    }
  }

  vm_map_unlock_read(map);
  vmspace_free(vm);

  if (entries) {
    *entries = info;
  }

  if (num_entries) {
    *num_entries = num;
  }

  return 0;
}

PAYLOAD_CODE static int proc_rw_mem(struct proc *p, void *ptr, size_t size, void *data, size_t *n, int write) {
  struct thread *td = curthread();
  struct iovec iov;
  struct uio uio;
  int r = 0;

  if (!p) {
    return -1;
  }

  if (size == 0) {
    if (n) {
      *n = 0;
    }

    return 0;
  }

  memset(&iov, 0, sizeof(iov));
  iov.iov_base = (uint64_t)data;
  iov.iov_len = size;

  memset(&uio, 0, sizeof(uio));
  uio.uio_iov = (uint64_t)&iov;
  uio.uio_iovcnt = 1;
  uio.uio_offset = (uint64_t)ptr;
  uio.uio_resid = (uint64_t)size;
  uio.uio_segflg = UIO_SYSSPACE;
  uio.uio_rw = write ? UIO_WRITE : UIO_READ;
  uio.uio_td = td;

  r = proc_rwmem(p, &uio);

  if (n) {
    *n = (size_t)((uint64_t)size - uio.uio_resid);
  }

  return r;
}

PAYLOAD_CODE static inline int proc_write_mem(struct proc *p, void *ptr, size_t size, void *data, size_t *n) {
  return proc_rw_mem(p, ptr, size, data, n, 1);
}

PAYLOAD_CODE int shellcore_patch(void) {
  return 0;
}

PAYLOAD_CODE int shellui_patch(void) {
  return 0;
}

PAYLOAD_CODE int remoteplay_patch(void) {
   return 0;
}

PAYLOAD_CODE void set_dipsw(int debug_patch) {
   return;
}

PAYLOAD_CODE void patch_debug_dipsw() {
  set_dipsw(1);
}

PAYLOAD_CODE void restore_retail_dipsw() {
  set_dipsw(0);
}

PAYLOAD_CODE void apply_patches() {
  shellui_patch();
  remoteplay_patch();
  shellcore_patch();
}

PAYLOAD_CODE void install_patches() {
  apply_patches();

  // Varies per FW
  if (fw_version <= 550) {
    // eventhandler_register_old(NULL, "system_suspend_phase3", &restore_retail_dipsw, NULL, EVENTHANDLER_PRI_PRE_FIRST); // < 5.50
    eventhandler_register_old(NULL, "system_resume_phase4", &apply_patches, NULL, EVENTHANDLER_PRI_LAST); // < 5.50
  } else {
    // eventhandler_register(NULL, "system_suspend_phase3", &restore_retail_dipsw, "hen_resume_patches", NULL, EVENTHANDLER_PRI_PRE_FIRST); // 5.50+ (Any changes after 6.72?)
    eventhandler_register(NULL, "system_resume_phase4", &apply_patches, "hen_resume_patches", NULL, EVENTHANDLER_PRI_LAST); // 5.50+ (Any changes after 6.72?)
  }
}
