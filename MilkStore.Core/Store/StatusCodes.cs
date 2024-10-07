using MilkStore.Core.Utils;

namespace MilkStore.Core.Constants
{
    public enum StatusCodes
    {
        [CustomName("Success")]
        OK = 200,

        [CustomName("Bad Request")]
        BadRequest = 400,

        [CustomName("Unauthorized")]
        Unauthorized = 401,

        [CustomName("Internal Server Error")]
        ServerError = 500,

        [CustomName("Not Found")]
        NotFound = 404
    }
}
