using MilkStore.Core.Base;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace MilkStore.Contract.Repositories.Entity
{
    public class PreOrders : BaseEntity
    {
        public string UserID { get; set; }
        public string ProductID { get; set; }
        public DateTime PreoderDate { get; set; }
        public string Status { get; set; }
        public int Quantity { get; set; }
        [ForeignKey("ProductID")]
        public virtual Products Products { get; set; }
    }
}
