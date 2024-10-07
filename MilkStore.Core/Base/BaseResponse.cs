using MilkStore.Core.Constants;
using MilkStore.Core.Utils;

namespace MilkStore.Core.Base
{
    public class BaseResponse<T>
    {
        public T? Data { get; set; }
        public string? Message { get; set; }
        public StatusCodes StatusCode { get; set; }
        public string? Code { get; set; }
        public BaseResponse(StatusCodes statusCode, string code, T? data, string? message)
        {
            Data = data;
            Message = message;
            StatusCode = statusCode;
            Code = code;
        }

        public BaseResponse(StatusCodes statusCode, string code, T? data)
        {
            Data = data;
            StatusCode = statusCode;
            Code = code;
        }

        public BaseResponse(StatusCodes statusCode, string code, string? message)
        {
            Message = message;
            StatusCode = statusCode;
            Code = code;
        }

        public static BaseResponse<T> OkResponse(T? data)
        {
            return new BaseResponse<T>(StatusCodes.OK, StatusCodes.OK.Name(), data);
        }
        public static BaseResponse<T> OkResponse(string? mess)
        {
            return new BaseResponse<T>(StatusCodes.OK, StatusCodes.OK.Name(), mess);
        }
        public static BaseResponse<T> NotFoundResponse(string? message)
        {
            return new BaseResponse<T>(StatusCodes.NotFound, StatusCodes.NotFound.Name(), message);
        }
    }
}
