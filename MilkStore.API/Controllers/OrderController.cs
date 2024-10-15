using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MilkStore.ModelViews.OrderModelViews;
using MilkStore.Contract.Services.Interface;
using MilkStore.Contract.Repositories.Entity;
using Microsoft.AspNetCore.Authorization;
using MilkStore.ModelViews.ResponseDTO;
using MilkStore.Services.Service;
using MilkStore.Core.Base;
using Microsoft.Extensions.Hosting;
using MilkStore.Core;
using MilkStore.Repositories.Entity;
using MilkStore.Core.Utils;
using System.Security.Claims;

namespace MilkStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class OrderController : ControllerBase
    {
        private readonly IOrderService _orderService;

        public OrderController(IOrderService orderService)
        {
            _orderService = orderService;
        }

        [HttpGet()]

        //[Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetAll(string? id, OrderStatus? orderStatus, PaymentStatus? paymentStatus, int index = 1, int pageSize = 10)
        {            
            BasePaginatedList<OrderResponseDTO> ord = await _orderService.GetAsync(id, orderStatus, paymentStatus, index, pageSize);
            return Ok(BaseResponse<BasePaginatedList<OrderResponseDTO>>.OkResponse(ord));
        }
      
        //[HttpPost]
        ////[Authorize(Roles = "Member")]
        //public async Task<IActionResult> Add([FromBody] CreateOrderDTO request)
        //{
        //    if (request == null || request.OrderItems == null || !request.OrderItems.Any())
        //    {
        //        return BadRequest("Order data or order items are missing.");
        //    }
        //    await _orderService.AddAsync(request.Order, request.OrderItems);
        //    return Ok(BaseResponse<string>.OkResponse("Order added successfully!"));            
        //}

        //[HttpPut("AddVoucher{id}")]
        ////[Authorize(Roles = "Guest, Member")]
        //public async Task<IActionResult> AddVoucher(string id, string item)
        //{            
        //    await _orderService.AddVoucher(id, item);
        //    return Ok(BaseResponse<string>.OkResponse("Voucher added successfully!"));           
        //}


        [HttpPut("Update{id}")]
        //[Authorize(Roles = "Guest, Member")]
        public async Task<IActionResult> Update(string id, OrderModelView item, [FromQuery] OrderStatus orderStatus, [FromQuery] PaymentStatus paymentStatus, [FromQuery] PaymentMethod paymentMethod)
        {            
            await _orderService.UpdateOrder(id, item, orderStatus, paymentStatus, paymentMethod);
            return Ok(BaseResponse<string>.OkResponse("Order was updated successfully!"));           
        }

        [HttpDelete("{id}")]
        //[Authorize(Roles = "Guest, Member")]
        public async Task<IActionResult> Delete(string id)
        {            
            await _orderService.DeleteAsync(id);
            return Ok(BaseResponse<string>.OkResponse("Order was deleted successfully!"));
            
        }
    }
}
