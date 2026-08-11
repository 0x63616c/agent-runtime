ALTER TABLE runtime.sandbox_host_dispatches
    DROP CONSTRAINT sandbox_host_dispatches_data_receipt_shape,
    DROP COLUMN data_receipt_id,
    DROP COLUMN data_receipt_digest,
    DROP COLUMN data_receipt_kind;
