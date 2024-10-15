using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using MilkStore.Core;
using MilkStore.ModelViews.OrderGiftModelViews;
using MilkStore.ModelViews.ResponseDTO;

namespace MilkStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class OrderGiftController : ControllerBase
    {
        private readonly IOrderGiftService _OGiftService;
        public OrderGiftController(IOrderGiftService GiftService)
        {
            _OGiftService = GiftService;
        }

        [HttpGet]
        //[Authorize(Roles = "Admin,Member")]
        public async Task<IActionResult> GetOrderGift(string? id)
        {
            IEnumerable<OrderGiftResponseDTO> Gift = await _OGiftService.GetOrderGift(id);
            return Ok(Gift);
        }

        [HttpPost("PostByMail")]
        //[Authorize(Roles = "Admin")]
        public async Task<IActionResult> CreateOrderGiftMail(string mail,OrderGiftModel OrderGiftModel)
        {
            await _OGiftService.CreateOrderGiftInputUser(mail, OrderGiftModel); 
            return Ok(BaseResponse<string>.OkResponse("Added successfully"));
        }
        [HttpPost("")]
        //[Authorize(Roles = "Admin")]
        public async Task<IActionResult> CreateOrderGift(OrderGiftModel OrderGiftModel)
        {
            await _OGiftService.CreateOrderGiftAuto(OrderGiftModel);
            return Ok(BaseResponse<string>.OkResponse("Added successfully"));
        }
        [HttpPut("{id}")]
        //[Authorize(Roles = "Admin")]
        public async Task<IActionResult> UpdateOrderGift(string id, [FromBody] OrderGiftModel OrderGiftModel, OrderGiftStatus ogs)
        {
            //await _OGiftService.SendMail_OrderGift(id);
            await _OGiftService.UpdateOrderGift(id, OrderGiftModel,ogs);
            
            return Ok(BaseResponse<string>.OkResponse("Updated successfully"));
            
        }

        [HttpDelete("{id}")]
        //[Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteOrderGift(string id)
        {
            await _OGiftService.DeleteOrderGift(id);
            return Ok(BaseResponse<string>.OkResponse("Deleted successfully"));
        }

    }
}
