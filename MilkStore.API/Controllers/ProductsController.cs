using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using MilkStore.ModelViews.ProductsModelViews;
using MilkStore.ModelViews.UserModelViews;
using MilkStore.Repositories.Entity;
using MilkStore.Services.Service;

namespace MilkStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ProductsController : ControllerBase
    {
        private readonly IProductsService _ProductsService;
        public ProductsController(IProductsService ProductsService)
        {
            _ProductsService = ProductsService;
        }
        [HttpGet]
        [Authorize(Roles = "Admin,Member")]
        public async Task<IActionResult> GetProducts(string? id)
        {
            try
            {
                // Lấy tất cả sản phẩm
                var products = await _ProductsService.GetProducts(id);

                // Kiểm tra xem có sản phẩm nào không
                if (products == null || !products.Any())
                {
                    return NotFound("Sản phẩm không tồn tại!!!");
                }

                return Ok(products); // Trả về danh sách sản phẩm
            }
            catch (Exception ex)
            {
                return StatusCode(500); // Trả về mã lỗi 500
            }
        }
        [HttpGet("GetByName")]
        public async Task<IActionResult> GetByName(string? name)
        {
            if (name == null)
            {
                return BadRequest("Tìm kiếm rỗng!!!");
            }
            else
            {
                IEnumerable<ProductsModel> product = await _ProductsService.GetProductsName(name);

                if (product == null || !product.Any())
                {
                    return BadRequest("Không tìm thấy sản phẩm!!!");
                }
                else
                {
                    return Ok(product);
                }
            }
        }
        [HttpGet("GetPagging")]
        [Authorize(Roles = "Admin,Member")]
        public async Task<IActionResult> Paging(int index, int size)
        {
            var paging = await _ProductsService.PagingProducts(index, size);
            return Ok(paging);
        }
        [HttpPost()]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> CreateProducts(ProductsModel ProductsModel)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new BaseException.BadRequestException("BadRequest", ModelState.ToString()));
            }
            Products Products = await _ProductsService.CreateProducts(ProductsModel);
            return Ok(BaseResponse<Products>.OkResponse(Products));
        }
        [HttpPut("{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> UpdateProduct(string id, [FromBody] ProductsModel productsModel)
        {
            if (!ModelState.IsValid)
            {
                return NotFound("Sản phẩm không tồn tại!!!");
            }

            try
            {
                var updatedProduct = await _ProductsService.UpdateProducts(id, productsModel);
                return Ok(updatedProduct);
            }
            catch (Exception ex)
            {
                return NotFound(new { message = ex.Message });
            }
        }
        [HttpDelete("{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteProduct(string id)
        {
            try
            {
                var deletedProduct = await _ProductsService.DeleteProducts(id);
                return Ok(deletedProduct); // Trả về sản phẩm đã bị xóa
            }
            catch (Exception ex)
            {
                return NotFound("Sản phẩm không tồn tại!!!"); // Trả về 404 nếu sản phẩm không tồn tại
            }
        }
    }
}
