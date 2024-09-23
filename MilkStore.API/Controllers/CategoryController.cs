using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using MilkStore.ModelViews.CategoryModelViews;
using MilkStore.Contract.Repositories.Entity;
using Microsoft.AspNetCore.Authorization;
namespace MilkStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CategoryController : ControllerBase
    {
        private readonly ICategoryService _CategoryService;
        public CategoryController(ICategoryService CategoryService)
        {
            _CategoryService = CategoryService;
        }
        [HttpGet]
        [Authorize(Roles = "Admin,Member")]
        public async Task<IActionResult> GetCategory(string? id)
        {
            try
            {
                var Category = await _CategoryService.GetCategory(id);

                if (Category == null || !Category.Any())
                {
                    return NotFound("Sản phẩm không tồn tại!!!");
                }

                return Ok(Category); // Trả về danh sách 
            }
            catch (Exception ex)
            {
                return StatusCode(500); // Trả về mã lỗi 500
            }
        }
        [HttpGet("GetPagging")]
        [Authorize(Roles = "Admin,Member")]
        public async Task<IActionResult> Paging(int index, int size)
        {
            var paging = await _CategoryService.PagingCategory(index, size);
            return Ok(paging);
        }
        [HttpPost()]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> CreateCategory(CategoryModel CategoryModel)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new BaseException.BadRequestException("BadRequest", ModelState.ToString()));
            }
            Category Category = await _CategoryService.CreateCategory(CategoryModel);
            return Ok(BaseResponse<Category>.OkResponse(Category));
        }
        [HttpPut("{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> UpdateProduct(string id, [FromBody] CategoryModel CategoryModel)
        {
            if (!ModelState.IsValid)
            {
                return NotFound("Sản phẩm không tồn tại!!!");
            }

            try
            {
                var updatedProduct = await _CategoryService.UpdateCategory(id, CategoryModel);
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
                var deletedProduct = await _CategoryService.DeleteCategory(id);
                return Ok(deletedProduct); // Trả về sản phẩm đã bị xóa
            }
            catch (Exception ex)
            {
                return NotFound("Sản phẩm không tồn tại!!!"); // Trả về 404 nếu sản phẩm không tồn tại
            }
        }
    }
}
