using MilkStore.Core.Base;
using MilkStore.Repositories.Entity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace MilkStore.Contract.Repositories.Entity
{
    public class Review : BaseEntity
    {
        public string UserID { get; set; }
        public string ProductID { get; set; }
        public int Rating { get; set; }
        public string Comment { get; set; }
        [ForeignKey("ProductID")]
        public virtual Products Products { get; set; }
    }
}
