using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using MilkStore.ModelViews.ResponseDTO;
using MilkStore.Services.Service;

namespace MilkStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class StatisticalController : ControllerBase
    {
        private readonly IStatisticalService _statisticalService;

        public StatisticalController(IStatisticalService statisticalService)
        {
            _statisticalService = statisticalService;
        }
        [HttpGet("revenue-stats")]
        public async Task<IActionResult> GetRevenueStats(int? day, int? month, int? year, DateTime? startDate, DateTime? endDate)
        {
            var revenue = await _statisticalService.GetRevenueStats(day, month, year, startDate, endDate);
            return Ok(revenue);
        }

        [HttpGet("revenue-by-employee")]
        public async Task<IActionResult> GetRevenueByEmployee(int? day, int? month, int? year, DateTime? startDate, DateTime? endDate)
        {
            var revenueByEmployee = await _statisticalService.GetRevenueByEmployee(day, month, year, startDate, endDate);
            return Ok(revenueByEmployee);
        }

        [HttpGet("revenue-by-product")]
        public async Task<IActionResult> GetRevenueByProduct(int? day, int? month, int? year, DateTime? startDate, DateTime? endDate)
        {
            var revenueByProduct = await _statisticalService.GetRevenueByProduct(day, month, year, startDate, endDate);
            return Ok(revenueByProduct);
        }

        [HttpGet("revenue-by-category")]
        public async Task<IActionResult> GetRevenueByCategory(int? day, int? month, int? year, DateTime? startDate, DateTime? endDate)
        {
            var revenueByCategory = await _statisticalService.GetRevenueByCategory(day, month, year, startDate, endDate);
            return Ok(revenueByCategory);
        }
        
    }
    }
