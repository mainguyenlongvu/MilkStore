using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.ModelViews.ResponseDTO
{
    public class ProductStockDTO
    {
        public string Id { get; set; } 
        public string ProductName { get; set; } 
        public int QuantityInStock { get; set; } 
        public string CategoryId { get; set; } 
    }
}
