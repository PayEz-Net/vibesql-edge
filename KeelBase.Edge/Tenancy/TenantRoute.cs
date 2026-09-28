namespace KeelBase.Edge.Tenancy;

public record TenantRoute(string TenantClientId, bool IsActive, StorageKind Kind);

public enum StorageKind { SharedSchema, DedicatedDatabase, DedicatedServer }
