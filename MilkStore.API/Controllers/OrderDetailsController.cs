using Microsoft.AspNetCore.Mvc;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.ModelViews.OrderDetailsModelView;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using Microsoft.AspNetCore.Authorization;
using MilkStore.ModelViews.ResponseDTO;
using MilkStore.Services.Service;
using MilkStore.Core;

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
        [HttpGet("Get_personal_order_detail")]
        public async Task<IActionResult> GetOrderDetails(string? orderId, OrderDetailStatus? orderDetailStatus, int page = 1, int pageSize = 10)
        {
            BasePaginatedList<OrderDetailResponseDTO> detail = await _orderDetailsService.ReadPersonalOrderDetails(orderId, orderDetailStatus, page, pageSize);
            return Ok(BaseResponse<BasePaginatedList<OrderDetailResponseDTO>>.OkResponse(detail));
        }
        [Authorize(Roles = "Admin, Staff")]
        // GET ALL
        [HttpGet("Get_all_order_detail")]
        public async Task<IActionResult> GetAllOrderDetails(string? orderId, string? userID, OrderDetailStatus? orderDetailStatus, int page = 1, int pageSize = 10)
        {
            BasePaginatedList<OrderDetailResponseDTO> detail = await _orderDetailsService.ReadAllOrderDetails(orderId, userID, orderDetailStatus, page, pageSize);
            return Ok(BaseResponse<BasePaginatedList<OrderDetailResponseDTO>>.OkResponse(detail));
        }
        // POST        
        [HttpPost("Add_to_cart")]
        public async Task<IActionResult> CreateOrderDetails(OrderDetailsModelView model)
        {
            await _orderDetailsService.CreateOrderDetails(model);
            return Ok(BaseResponse<string>.OkResponse("Đã tạo chi tiết đơn hàng!"));
        }

        // PUT        
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateOrderDetails(string id, OrderDetailsModelView model)
        {            
            OrderDetails detail = await _orderDetailsService.UpdateOrderDetails(id, model);
            return Ok(BaseResponse<string>.OkResponse("Chi tiết đơn hàng được cập nhật thành công!"));
        }

        // DELETE        
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteOrderDetails(string id)
        {            
            await _orderDetailsService.DeleteOrderDetails(id);
            return Ok(BaseResponse<string>.OkResponse("Chi tiết đơn hàng được cập nhật thành công!"));            
        }
    }
}

