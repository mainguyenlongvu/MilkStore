using Microsoft.AspNetCore.Mvc;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.ModelViews;
using MilkStore.ModelViews.OrderDetailsModelView;
using MilkStore.Services.Service;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using Microsoft.AspNetCore.Authorization;

namespace MilkStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class OrderDetailsController : ControllerBase
    {
        private readonly IOrderDetailsService _orderDetailsService;
        public OrderDetailsController(IOrderDetailsService orderDetailsService)
        {
            _orderDetailsService = orderDetailsService;
        }

        // GET
        [HttpGet]
        public async Task<IActionResult> GetOrderDetails(string? orderId, int page=1, int pageSize=10)
        {
            IList<OrderDetails> detail = (IList<OrderDetails>)await _orderDetailsService.ReadOrderDetails(orderId, page, pageSize);
            return Ok(BaseResponse<IList<OrderDetails>>.OkResponse(detail));
        }

        // POST
        [Authorize(Roles = "Guest, Member")]
        [HttpPost]
        public async Task<IActionResult> CreateOrderDetails(OrderDetailsModelView model)
        {
            try
            {
                await _orderDetailsService.CreateOrderDetails(model);
                return Ok(new { message = "Thêm thành công" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        // PUT
        [Authorize(Roles = "Guest, Member")]
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateOrderDetails(string id, OrderDetailsModelView model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new BaseException.BadRequestException("BadRequest", ModelState.ToString()));
            }
            OrderDetails detail = await _orderDetailsService.UpdateOrderDetails(id, model);
            
            return Ok(new { message = "Sửa thành công" });
        }

        // DELETE
        [Authorize(Roles = "Guest, Member")]
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteOrderDetails(string id)
        {
            try
            {
                await _orderDetailsService.DeleteOrderDetails(id);
                return Ok(new { message = "Xóa thành công" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }
    }
}
