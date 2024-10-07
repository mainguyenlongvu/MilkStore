using MilkStore.Core.Constants;

namespace MilkStore.Core.Base
{
    public class BaseException : Exception
    {
        public class ErrorException : Exception
        {
            public StatusCodes StatusCode { get; }

            public ErrorDetail ErrorDetail { get; }

            public ErrorException(StatusCodes statusCode, string errorCode, string message)
            {
                StatusCode = statusCode;
                ErrorDetail = new ErrorDetail
                {
                    ErrorCode = errorCode,
                    ErrorMessage = message
                };
            }
            public ErrorException(StatusCodes statusCode, ErrorDetail errorDetail)
            {
                StatusCode = statusCode;
                ErrorDetail = errorDetail;
            }
        }
        public class ErrorDetail
        {
            public string? ErrorCode { get; set; }

            public object? ErrorMessage { get; set; }
        }
    }
}
