using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.ModelViews.ResponseDTO
{
    public class EmployeeRevenueDTO
    {
        public string? EmployeeId { get; set; }
        public string? EmployeeName { get; set; }
        public double TotalRevenue { get; set; }
    }
}
