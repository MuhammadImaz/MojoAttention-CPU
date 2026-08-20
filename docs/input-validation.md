# Attention input validation

The Python boundary validates Q, K, V, and caller-owned output against the protected Kernel Contract before invoking native code. It returns the first stable error in protected precedence order and never performs implicit device moves, casts, contiguous copies, clones, fallback, or replacement output allocation.

Validation covers CPU float32 rank-4 BHSD tensors, equal supported shapes, standard contiguous strided storage, finite values with inclusive `abs(x)<=20`, storage-range non-overlap, and output shape/layout/non-overlap. Opaque layouts and unresolved conjugate/negative views are rejected because their logical values do not directly match native storage. Storage checks use PyTorch storage identity, storage offset, element size, and byte ranges; object identity alone is insufficient.

`validate_and_dispatch` accepts an injected synchronous dispatch callable. Rejected inputs produce zero calls and leave all tensors unchanged. A valid request receives exactly one call using the original tensor objects. Under inference mode, the caller-owned output is marked unwritten with a reserved float32 NaN bit pattern. Any nonfinite value after return produces `KERNEL-INCOMPLETE-WRITE`: for the protected finite input domain, causal attention's stable-softmax result must be finite, so a nonfinite native result cannot satisfy the complete-write contract. Story 2.4 supplies the real Mojo dispatch implementation and native exception translation.

Ownership and lifetime are established by accepting live PyTorch `Tensor` objects and requiring synchronous completion before return. No native pointer is retained by this story.
