namespace KeelBase.Edge.Limits;

public class TierLimitOptions
{
    public long ApiCallsPerDay { get; set; } = 10000;
    public long DocumentReadsPerDay { get; set; } = 20000;
    public long DocumentWritesPerDay { get; set; } = 2000;
    public long SchemaOpsPerDay { get; set; } = 200;
    public long BatchOpsPerDay { get; set; } = 100;
}
