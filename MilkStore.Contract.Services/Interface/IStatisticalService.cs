using MilkStore.ModelViews.ResponseDTO;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.Contract.Services.Interface
{
    public interface IStatisticalService
    {
        Task<double> GetRevenueStats(int? day, int? month, int? year, DateTime? startDate, DateTime? endDate);
        Task<List<EmployeeRevenueDTO>> GetRevenueByEmployee(int? day, int? month, int? year, DateTime? startDate, DateTime? endDate);
        Task<List<ProductRevenueDTO>> GetRevenueByProduct(int? day, int? month, int? year, DateTime? startDate, DateTime? endDate);
        Task<List<CategoryRevenueDTO>> GetRevenueByCategory(int? day, int? month, int? year, DateTime? startDate, DateTime? endDate);

    }
}
