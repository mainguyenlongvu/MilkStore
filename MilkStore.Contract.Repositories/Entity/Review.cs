using MilkStore.Core.Base;
using MilkStore.Core.Utils;
using MilkStore.Repositories.Entity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace MilkStore.Contract.Repositories.Entity
{
    public class Review : BaseEntity
    {
        public required Guid UserID { get; set; }
        public required string OrderDetailID { get; set; }
        public required string ProductsID { get; set; }
        public required string OrderID { get; set; }        
        [Range(1, 5, ErrorMessage = "Đánh giá từ 1 đến 5 sao")]
        public required int Rating { get; set; }
        public string? Comment { get; set; }                
        public virtual OrderDetails OrderDetails { get; set; }        
        public virtual ApplicationUser User { get; set; }
    }
}
