using System.Text.Json.Serialization;

namespace Vibe.Edge.Models;

public class ApiResponse<T>
{
    [JsonPropertyName("success")]
    public bool Success { get; set; }

    [JsonPropertyName("message")]
    public string Message { get; set; } = string.Empty;

    [JsonPropertyName("operation_code")]
    public string OperationCode { get; set; } = string.Empty;

    [JsonPropertyName("time_stamp")]
    public string TimeStamp { get; set; } = string.Empty;

    [JsonPropertyName("request_id")]
    public string RequestId { get; set; } = string.Empty;

    [JsonPropertyName("data")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public T? Data { get; set; }

    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ApiError? Error { get; set; }

    [JsonPropertyName("meta")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public object? Meta { get; set; }

    public static ApiResponse<T> SuccessResponse(T data, string message, string operationCode, string? requestId = null)
    {
        return new ApiResponse<T>
        {
            Success = true,
            Message = message,
            OperationCode = operationCode,
            TimeStamp = DateTime.UtcNow.ToString("o"),
            RequestId = requestId ?? string.Empty,
            Data = data
        };
    }

    public static ApiResponse<T> FailureResponse(string message, string errorCode, string? detail = null, string? requestId = null)
    {
        return new ApiResponse<T>
        {
            Success = false,
            Message = message,
            OperationCode = errorCode,
            TimeStamp = DateTime.UtcNow.ToString("o"),
            RequestId = requestId ?? string.Empty,
            Error = new ApiError
            {
                Code = errorCode,
                Detail = detail
            }
        };
    }
}

public class ApiError
{
    [JsonPropertyName("code")]
    public string Code { get; set; } = string.Empty;

    [JsonPropertyName("detail")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Detail { get; set; }
}
