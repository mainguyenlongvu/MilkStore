using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MilkStore.Contract.Services.Interface;
using MilkStore.Services.Service;

namespace MilkStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class StatisticalProductController : ControllerBase
    {
        private readonly IStatisticalProductService _statisticalProductService;
        public StatisticalProductController(IStatisticalProductService statisticalProduct)
        {
            _statisticalProductService = statisticalProduct;
        }
        [HttpGet("top-selling-products")]
        public async Task<IActionResult> GetTopSellingProducts(
            [FromQuery] int topN = 10,
            [FromQuery] DateTime? startDate = null,
            [FromQuery] DateTime? endDate = null,
            [FromQuery] string? productName = null,
            [FromQuery] string? categoryName = null)
        {
            var result = await _statisticalProductService.GetTopSellingProducts(topN, startDate, endDate, productName, categoryName);

            return result != null && (result is not IEnumerable<object> enumerable || enumerable.Any()) ? Ok(result) : NotFound();
        }

        [HttpGet("low-stock-products")]
        public async Task<IActionResult> GetLowStockProducts([FromQuery] int threshold)
        {
            var result = await _statisticalProductService.GetLowStockProducts(threshold);

            return result != null && (result is not IEnumerable<object> enumerable || enumerable.Any()) ? Ok(result) : NotFound();
        }
    }
}
